/*
 * Copyright (c) 2011-2016 Progress Software Corporation and/or its subsidiaries or affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.marklogic.mapreduce.utilities;

import java.io.IOException;
import java.net.URI;
import java.util.ArrayDeque;
import java.util.Deque;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.conf.Configuration;

import com.marklogic.mapreduce.DocumentURI;
import com.marklogic.mapreduce.MarkLogicConstants;

/**
 * Class containing utility functions for URI manipulations.
 * 
 * @author jchen
 */
public class URIUtil implements MarkLogicConstants {
    public static final Log LOG = LogFactory.getLog(URIUtil.class);

    /**
     * Apply URI replacement configuration option to a URI source string.  The
     * configuration option is a list of comma separated pairs of regex 
     * patterns and replacements.  Validation of the configuration is done at
     * command parsing time.
     * 
     * @param uriSource
     * @param conf
     * @return result URI string
     */
    public static String applyUriReplace(String uriSource, Configuration conf) {
        if (uriSource == null) return null;
        String[] uriReplace = conf.getStrings(OUTPUT_URI_REPLACE);
        if (uriReplace == null) return uriSource;
        for (int i = 0; i < uriReplace.length - 1; i += 2) {
            String replacement = uriReplace[i+1].trim();
            replacement = replacement.substring(1, replacement.length()-1);
            uriSource = uriSource.replaceAll(uriReplace[i], replacement);
        }
        return uriSource;
    }
    
    /**
     * Apply URI prefix and suffix configuration option to a URI source string.
     * 
     * @param uriSource
     * @param conf
     * @return result URI string
     */
    public static String applyPrefixSuffix(String uriSource, 
            Configuration conf) {
        if (uriSource == null) return null;
        String prefix = conf.get(OUTPUT_URI_PREFIX);
        String suffix = conf.get(OUTPUT_URI_SUFFIX);
        if (prefix == null && suffix == null) {
            return uriSource;
        }
        int len = uriSource.length() +
                (prefix != null ? prefix.length() : 0) +
                (suffix != null ? suffix.length() : 0);
        StringBuilder uriBuf = new StringBuilder(len);
        if (prefix != null) {
            uriBuf.append(prefix);
        }
        uriBuf.append(uriSource);
        if (suffix != null) {
            uriBuf.append(suffix);
        }
        return uriBuf.toString();
    }
    
    public static String getPathFromURI(DocumentURI uri)  {
        String uriStr = uri.getUri();
        try {
            URI child = new URI(uriStr);
            String childPath;
            if (child.isOpaque()) {
                childPath = child.getSchemeSpecificPart();
            } else {
                childPath = child.getPath();
            }
            return childPath;
        } catch (Exception ex) {
            LOG.warn("Error parsing URI " + uriStr + ".");
            return uriStr;
        }
    }

    /**
     * Resolve a document-URI-derived child path against a concrete base
     * output directory (e.g. -output_file_path), and verify that the
     * result does not escape that directory. Protects against path
     * traversal (CWE-22) when a document URI contains ".." segments.
     * <p>
     * Normalization is purely lexical (string-based collapsing of "."
     * and ".." segments), with no filesystem I/O. This makes it safe and
     * correct to use for both local filesystem paths and distributed
     * filesystem paths (e.g. HDFS), since it never needs the path to
     * actually exist and never follows symlinks.
     *
     * @param baseDir concrete, non-root base output directory, using '/'
     *                as path separator
     * @param childPath path derived from a document URI; may be absolute
     *                  (leading '/') or relative, and may contain ".."
     *                  segments
     * @return the normalized, safe absolute path string; always equal to
     *         or nested under the normalized form of baseDir
     * @throws IOException if the resolved path would escape baseDir
     */
    public static String resolveContainedPath(String baseDir,
            String childPath) throws IOException {
        String normalizedBase = normalizeSlashPath(baseDir);
        String combined = (childPath.length() > 0 && childPath.charAt(0) == '/') ?
                normalizedBase + childPath : normalizedBase + "/" + childPath;
        String normalized = normalizeSlashPath(combined);
        if (!normalized.equals(normalizedBase) &&
                !normalized.startsWith(normalizedBase + "/")) {
            throw new IOException("Document URI resolves outside of " +
                "output path \"" + baseDir + "\": " + childPath);
        }
        return normalized;
    }

    /**
     * Convert a document URI's path into a name safe to use as a
     * ZipEntry in an archive output, rejecting any URI whose path would
     * resolve above the archive's own root once ".." segments are
     * applied (a.k.a. "zip slip", CWE-22). Unlike
     * {@link #resolveContainedPath(String, String)}, there is no real
     * base directory to canonicalize against at archive-write time, so
     * any attempt to walk above the archive root is rejected outright
     * rather than clamped.
     *
     * @param uri raw document URI string, as would otherwise be used
     *            directly as a ZipEntry name
     * @return a normalized, traversal-safe, '/'-relative entry name
     *         (no leading '/', no ".." components)
     * @throws IOException if the URI would resolve above the archive root
     */
    public static String sanitizeZipEntryName(String uri) throws IOException {
        String[] parts = uri.split("/");
        Deque<String> stack = new ArrayDeque<String>();
        for (String part : parts) {
            if (part.isEmpty() || ".".equals(part)) {
                continue;
            } else if ("..".equals(part)) {
                if (stack.isEmpty()) {
                    throw new IOException("Document URI would escape the " +
                        "archive root: " + uri);
                }
                stack.removeLast();
            } else {
                stack.addLast(part);
            }
        }
        return join(stack);
    }

    /**
     * Lexically normalize a '/'-separated path, collapsing "." and ".."
     * segments. A ".." that would walk above the root of an absolute
     * path (or above the first segment of a relative path) simply has
     * no effect, pinning the result at the root instead of escaping it,
     * which gives callers a stable, always-rooted string to compare
     * against. No filesystem I/O is performed and the path need not
     * exist.
     */
    private static String normalizeSlashPath(String path) {
        boolean absolute = path.length() > 0 && path.charAt(0) == '/';
        String[] parts = path.split("/");
        Deque<String> stack = new ArrayDeque<String>();
        for (String part : parts) {
            if (part.isEmpty() || ".".equals(part)) {
                continue;
            } else if ("..".equals(part)) {
                if (!stack.isEmpty()) {
                    stack.removeLast();
                }
            } else {
                stack.addLast(part);
            }
        }
        String joined = join(stack);
        return absolute ? "/" + joined : joined;
    }

    private static String join(Deque<String> stack) {
        StringBuilder sb = new StringBuilder();
        boolean first = true;
        for (String part : stack) {
            if (!first) {
                sb.append('/');
            }
            sb.append(part);
            first = false;
        }
        return sb.toString();
    }
}
