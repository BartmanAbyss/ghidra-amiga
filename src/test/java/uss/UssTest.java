package uss;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

import java.io.File;
import java.nio.file.AccessMode;

import org.junit.Test;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.FileByteProvider;
import ghidra.formats.gfilesystem.FSRL;

public class UssTest {
	private static UssFile loadUss(String pathname) throws Exception {
		return new UssFile(new BinaryReader(new FileByteProvider(new File(pathname), FSRL.fromString("file://dir/subdir"), AccessMode.READ), false), null, null);
	}

	@Test
	public void testUss() throws Exception {
		loadUss("test/uss/desertdream-dots.uss");
		loadUss("test/uss/bobble-title.uss"); // 2MB Chip, 8MB A3000 Fast
		loadUss("test/uss/done endscreen.uss"); // 2MB Chip, 4MB Z2 Fast
	}
}
