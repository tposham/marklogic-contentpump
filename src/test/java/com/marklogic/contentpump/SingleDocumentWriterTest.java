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
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

import org.apache.commons.io.FileUtils;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.Text;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.marklogic.mapreduce.ContentType;
import com.marklogic.mapreduce.DocumentURI;
import com.marklogic.mapreduce.MarkLogicDocument;

/**
 * Unit tests for the path-traversal fix in {@link SingleDocumentWriter}
 * (MLE-33527, CWE-22: mlcp export writes files outside
 * -output_file_path when a document URI contains ".." segments). Uses
 * real local temp directories (LocalFileSystem) but no live MarkLogic
 * server.
 */
public class SingleDocumentWriterTest {

    private File outDir;
    private File outsideSentinel;
    private Configuration conf;

    @Before
    public void setUp() throws IOException {
        outDir = Files.createTempDirectory("mlcp-sdw-test-out").toFile();
        // A file living just outside the output dir, in its parent -- this
        // stands in for an arbitrary file elsewhere on the export host
        // (e.g. /tmp/mlcp-traversal-proof.txt in the live PoC).
        outsideSentinel = new File(outDir.getParentFile(), "sentinel.txt");
        FileUtils.writeStringToFile(outsideSentinel,
            "PRISTINE-SENTINEL-DO-NOT-OVERWRITE", "UTF-8");
        conf = new Configuration();
    }

    @After
    public void tearDown() throws IOException {
        FileUtils.deleteDirectory(outDir);
        FileUtils.deleteQuietly(outsideSentinel);
    }

    @Test
    public void escapingUriDoesNotOverwriteFileOutsideOutputDir()
            throws Exception {
        // relative traversal count doesn't matter -- any amount of ".."
        // that walks above outDir must be rejected
        String uri = "/../" + outsideSentinel.getName();
        write(uri, "ATTACKER-CONTROLLED-CONTENT");

        assertEquals("PRISTINE-SENTINEL-DO-NOT-OVERWRITE",
            FileUtils.readFileToString(outsideSentinel, "UTF-8"));
        assertFalse("no file should be created anywhere under outDir "
            + "for an escaping URI",
            new File(outDir, outsideSentinel.getName()).exists());
    }

    @Test
    public void deeplyEscapingUriDoesNotEscapeOutputDir() throws Exception {
        String uri = "/../../../../../../../../tmp/mlcp-traversal-proof.txt";
        write(uri, "ATTACKER-CONTROLLED-CONTENT");

        File wouldBeEscapeTarget = new File("/tmp/mlcp-traversal-proof.txt");
        assertFalse("test must not depend on /tmp/mlcp-traversal-proof.txt "
            + "pre-existing", wouldBeEscapeTarget.exists());
    }

    @Test
    public void legitimateNestedUriIsExportedInsideOutputDir()
            throws Exception {
        write("/reports/quarterly.txt", "BENIGN-CONTROL");

        File expected = new File(outDir, "reports/quarterly.txt");
        assertTrue(expected.exists());
        assertEquals("BENIGN-CONTROL",
            FileUtils.readFileToString(expected, "UTF-8"));
    }

    @Test
    public void dotDotThatStaysInsideOutputDirStillWorks() throws Exception {
        // "/a/../b/ok.txt" normalizes to "/b/ok.txt", which is still
        // inside outDir -- the fix must not break this legitimate,
        // documented directory-step behavior.
        write("/a/../b/ok.txt", "STILL-FINE");

        File expected = new File(outDir, "b/ok.txt");
        assertTrue(expected.exists());
        assertEquals("STILL-FINE",
            FileUtils.readFileToString(expected, "UTF-8"));
        assertFalse(new File(outDir, "a").exists());
    }

    private void write(String uriStr, String text) throws Exception {
        SingleDocumentWriter writer =
            new SingleDocumentWriter(new Path(outDir.getAbsolutePath()), conf);
        DocumentURI uri = new DocumentURI(uriStr);
        MarkLogicDocument doc = mock(MarkLogicDocument.class);
        when(doc.getContentType()).thenReturn(ContentType.TEXT);
        when(doc.getContentAsText()).thenReturn(new Text(text));
        writer.write(uri, doc);
    }
}
