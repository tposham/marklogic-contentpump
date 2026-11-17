/*
 * Copyright (c) 2011-2026 Progress Software Corporation and/or its subsidiaries or affiliates. All Rights Reserved.
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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;

import org.junit.Test;

/**
 * Unit tests for the path-traversal containment checks added for
 * MLE-33527 (CWE-22: mlcp export writes files outside
 * -output_file_path when a document URI contains ".." segments).
 * Pure path-math, no filesystem I/O or live server required.
 */
public class URIUtilTest {

    private static final String OUT_DIR = "/work/out";

    // -- resolveContainedPath: used by SingleDocumentWriter (document export) --

    @Test
    public void rejectsSimpleTraversal() {
        assertEscapes("/../../../../../../../../tmp/evil.txt");
    }

    @Test
    public void rejectsTraversalWithoutLeadingSlash() {
        assertEscapes("../../etc/passwd");
    }

    @Test
    public void rejectsTraversalThatExactlyReachesParentOfBase() {
        // "/work/out" + "/.." -> "/work", which is NOT inside "/work/out"
        assertEscapes("/..");
    }

    @Test
    public void allowsNestedDirectorySteps() throws IOException {
        String resolved = URIUtil.resolveContainedPath(OUT_DIR, "/reports/quarterly.txt");
        assertEquals("/work/out/reports/quarterly.txt", resolved);
    }

    @Test
    public void allowsRelativeChildPath() throws IOException {
        String resolved = URIUtil.resolveContainedPath(OUT_DIR, "reports/quarterly.txt");
        assertEquals("/work/out/reports/quarterly.txt", resolved);
    }

    @Test
    public void allowsDotDotThatStaysInsideBase() throws IOException {
        // "/a/../b/ok.txt" normalizes to "/b/ok.txt", which is still under baseDir
        String resolved = URIUtil.resolveContainedPath(OUT_DIR, "/a/../b/ok.txt");
        assertEquals("/work/out/b/ok.txt", resolved);
    }

    @Test
    public void allowsChildPathEqualToBase() throws IOException {
        String resolved = URIUtil.resolveContainedPath(OUT_DIR, "/");
        assertEquals(OUT_DIR, resolved);
    }

    @Test
    public void rejectsTraversalHiddenAfterLegitimateSegments() {
        // starts legitimate, then walks all the way back out and beyond
        assertEscapes("/reports/../../../../../../etc/passwd");
    }

    private static void assertEscapes(String childPath) {
        try {
            String resolved = URIUtil.resolveContainedPath(OUT_DIR, childPath);
            fail("Expected an IOException for escaping child path \"" + childPath +
                "\" but it resolved to: " + resolved);
        } catch (IOException expected) {
            assertTrue(expected.getMessage().contains(childPath));
        }
    }

    // -- sanitizeZipEntryName: used by OutputArchive / ArchiveWriter (archive export) --

    @Test
    public void zipEntryRejectsTraversalAboveArchiveRoot() {
        assertZipEntryEscapes("/../../../../../../../../tmp/evil.txt");
    }

    @Test
    public void zipEntryRejectsSingleDotDot() {
        assertZipEntryEscapes("..");
    }

    @Test
    public void zipEntryAllowsNestedDirectorySteps() throws IOException {
        assertEquals("reports/quarterly.txt",
            URIUtil.sanitizeZipEntryName("/reports/quarterly.txt"));
    }

    @Test
    public void zipEntryAllowsDotDotThatStaysInsideRoot() throws IOException {
        assertEquals("b/ok.txt",
            URIUtil.sanitizeZipEntryName("/a/../b/ok.txt"));
    }

    private static void assertZipEntryEscapes(String uri) {
        try {
            String resolved = URIUtil.sanitizeZipEntryName(uri);
            fail("Expected an IOException for escaping uri \"" + uri +
                "\" but it resolved to: " + resolved);
        } catch (IOException expected) {
            assertTrue(expected.getMessage().contains(uri));
        }
    }
}
