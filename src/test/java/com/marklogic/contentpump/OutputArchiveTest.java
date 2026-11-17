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
package com.marklogic.contentpump;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.hadoop.conf.Configuration;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Unit tests for the zip-slip fix in {@link OutputArchive}
 * (MLE-33527, CWE-22: a document URI containing ".." segments must
 * not be able to produce a zip entry that would extract outside the
 * archive). Uses a real local temp directory but no live MarkLogic
 * server.
 */
public class OutputArchiveTest {

    private File workDir;
    private Configuration conf;

    @Before
    public void setUp() throws IOException {
        workDir = Files.createTempDirectory("mlcp-archive-test").toFile();
        conf = new Configuration();
    }

    @After
    public void tearDown() throws IOException {
        FileUtils.deleteDirectory(workDir);
    }

    @Test
    public void rejectsEntryThatWouldEscapeArchiveRoot() throws IOException {
        OutputArchive archive = new OutputArchive(
            new File(workDir, "archive-TEXT").getAbsolutePath(), conf);
        try {
            archive.write("/../../../../../../../../tmp/evil.txt",
                "ATTACKER-CONTROLLED".getBytes("UTF-8"), true);
            fail("Expected an IOException for an escaping zip entry name");
        } catch (IOException expected) {
            assertTrue(expected.getMessage().contains("escape"));
        } finally {
            archive.close();
        }
    }

    @Test
    public void legitimateEntryIsStoredAndNoTraversalEntryLeaksIn()
            throws IOException {
        OutputArchive archive = new OutputArchive(
            new File(workDir, "archive-TEXT").getAbsolutePath(), conf);
        archive.write("/reports/quarterly.txt",
            "BENIGN-CONTROL".getBytes("UTF-8"), true);
        try {
            archive.write("/../../../../../../../../tmp/evil.txt",
                "ATTACKER-CONTROLLED".getBytes("UTF-8"), true);
            fail("Expected an IOException for an escaping zip entry name");
        } catch (IOException expected) {
            // expected -- the sanitize check fires before any entry is
            // written for this (rejected) document
        } finally {
            archive.close();
        }

        File zipFile = findZipFile(workDir);
        try (ZipFile zip = new ZipFile(zipFile)) {
            ZipEntry entry = zip.getEntry("reports/quarterly.txt");
            assertTrue("expected legitimate entry to be present",
                entry != null);
            assertEquals("BENIGN-CONTROL",
                IOUtils.toString(zip.getInputStream(entry), "UTF-8"));

            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry e = entries.nextElement();
                assertFalse("zip must not contain any traversal entry: "
                    + e.getName(), e.getName().contains(".."));
            }
        }
    }

    private static File findZipFile(File dir) {
        File[] zips = dir.listFiles((d, name) -> name.endsWith(".zip"));
        assertTrue("expected exactly one zip file in " + dir,
            zips != null && zips.length == 1);
        return zips[0];
    }
}
