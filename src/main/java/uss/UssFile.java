package uss;

import java.io.IOException;
import java.util.ArrayList;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class UssFile {
	public String romId, emuName, emuVersion, description;
	public long cpuModel = 0, cpuFlags = 0, cpuExtraFlags = 0, chipsetFlags = 0;
	public ArrayList<MemoryRegion> memBlocks = new ArrayList<>();

	public static boolean isUssFile(BinaryReader reader) {
		try {
			String asf = reader.readNextAsciiString(4);
			return asf.equals("ASF");
		} catch(IOException ex) {
			return false;
		}
	}

	private class Chunk {
		public String name;
		public byte[] buffer;
	}

	private static final int chipMemBase = 0x0000_0000;
	private static final int bogoMemBase = 0x00c0_0000;
	private static final int a3000MemBase = 0x0800_0000;
	private static final int z2MemBase = 0x0020_0000;
	private static final int z3MemBase = 0x4000_0000;

	private long fastMem0Addr = 0, fastMem1Addr = 0, z3fastMemAddr = 0, a3kMemAddr = a3000MemBase;

	private Chunk readChunk(BinaryReader reader) {
		try {
			if(reader.getPointerIndex() + 3 * 4 > reader.length())
				return null;
			var chunk = new Chunk();
			// see WinUAE:savestate.cpp@restore_chunk
			chunk.name = reader.readNextAsciiString(4);
			var len = (int)reader.readNextUnsignedInt() - 4 - 4 - 4;
			var flags = reader.readNextUnsignedInt();
			if((flags & 1 ) != 0) {
				// zuncompress
				var uncompressedLen = (int)reader.readNextUnsignedInt();
				chunk.buffer = new byte[uncompressedLen];
				len -= 4;
				var inflater = new Inflater();
				inflater.setInput(reader.readNextByteArray(len));
				var resultLen = inflater.inflate(chunk.buffer);
				assert(resultLen == uncompressedLen);
			} else {
				chunk.buffer = reader.readNextByteArray(len);
			}
			// alignment
			reader.setPointerIndex(reader.getPointerIndex() + 4 - (len & 3)); // yes, bug in WinUAE
			System.out.format("Chunk '%s' size '%s' (%d)\n", chunk.name, len, chunk.buffer.length);
			return chunk;
		} catch(IOException | DataFormatException e) {
			return null;
		}
	}

	public UssFile(BinaryReader reader, TaskMonitor monitor, MessageLog log) throws IOException, CancelledException {
		reader.setLittleEndian(false);
		var chunk = readChunk(reader);
		if(chunk == null || !chunk.name.equals("ASF"))
			throw new IOException("missing 'ASF' marker: not USS?");
		readHeader(chunk.buffer);
		int framCount = 0, zramCount = 0;
		while(true) {
			chunk = readChunk(reader);
			if(chunk == null || chunk.name.equals("END") || chunk.name.isEmpty())
				break;
			switch(chunk.name) {
			// TODO: CHIP, SPRx, AUDx
			case "CPU":  
				readCpu(chunk.buffer); 
				break;
			case "CPUX": 
				readCpuExtra(chunk.buffer); 
				break;
			case "CHIP": 
				readChip(chunk.buffer); 
				break;
			case "ROM":
				readRom(chunk.buffer); 
				break;
			case "CRAM": 
				memBlocks.add(new MemoryRegion("CHIP", chipMemBase, chunk.buffer)); 
				break;
			case "BRAM": 
				memBlocks.add(new MemoryRegion("BOGO", bogoMemBase, chunk.buffer)); 
				break;
			case "FRAM": 
				assert(framCount <= 1);
				var addr = framCount == 0 ? fastMem0Addr : fastMem1Addr;
				assert(addr != 0);
				memBlocks.add(new MemoryRegion(String.format("FRAM%d", framCount), addr, chunk.buffer)); 
				framCount++;
				break;
			case "ZRAM":
				assert(z3fastMemAddr != 0);
				memBlocks.add(new MemoryRegion(String.format("ZRAM%d", zramCount), z3fastMemAddr, chunk.buffer)); 
				z3fastMemAddr += chunk.buffer.length;
				zramCount++;
				break;
			case "A3K1":
			case "A3K2":
				memBlocks.add(new MemoryRegion(chunk.name, a3kMemAddr, chunk.buffer));
				a3kMemAddr += chunk.buffer.length;
				break;
			//case "ZCRM": // Zorro3 Chipmem
			case "EXPA": 
				readExpansion(chunk.buffer); 
				break;
			}
		}
		for(var mem: memBlocks)
			System.out.format("*Mem* $%08x+$%08x = '%s'\n", mem.start, mem.length, mem.name);
	}

	private void readExpansion(byte[] buffer) throws IOException {
		var reader = new BinaryReader(new ByteArrayProvider(buffer), false);
		fastMem0Addr = reader.readNextUnsignedInt();
		z3fastMemAddr = reader.readNextUnsignedInt();
		var gfxmem_bank = reader.readNextUnsignedInt();
		var rtarea_base = reader.readNextUnsignedInt();
		fastMem1Addr = reader.readNextUnsignedInt();
		System.out.format("  fram0 $%x, z3ram $%x, fram1 $%x\n", fastMem0Addr, z3fastMemAddr, fastMem1Addr);
	}

	private void readHeader(byte[] buffer) throws IOException {
		var reader = new BinaryReader(new ByteArrayProvider(buffer), false);
		reader.setPointerIndex(4);
		emuName = reader.readNextNullTerminatedAsciiString();
		emuVersion = reader.readNextNullTerminatedAsciiString();
		description = reader.readNextNullTerminatedAsciiString();
		System.out.format("  Saved with '%s %s', description: '%s'\n", emuName, emuVersion, description);
	}

	private void readRom(byte[] buffer) throws IOException {
		var reader = new BinaryReader(new ByteArrayProvider(buffer), false);
		var start = reader.readNextUnsignedInt();
		var size = reader.readNextUnsignedInt();
		reader.setPointerIndex(20);
		romId = reader.readNextNullTerminatedAsciiString();
		System.out.format("  ROM: '%s' @ $%08x+$%08x\n", romId, start, size);
		memBlocks.add(new MemoryRegion("ROM", start, size));
	}

	private void readChip(byte[] buffer) {
	}

	private void readCpuExtra(byte[] buffer) {
	}

	private void readCpu(byte[] buffer) {
	}

	public static class MemoryRegion {
		public String name;
		public long start;
		public long length;
		public byte[] content;

		public MemoryRegion(long start, long length) {
			this.start = start;
			this.length = length;
		}

		public MemoryRegion(String name, long start, long length) {
			this.name = name;
			this.start = start;
			this.length = length;
		}

		public MemoryRegion(String name, long start, byte[] content) {
			this(name, start, content.length);
			this.content = content;
		}
	}
}
