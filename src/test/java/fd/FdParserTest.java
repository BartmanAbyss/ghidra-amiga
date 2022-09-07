package fd;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.File;

import org.junit.Test;

import fd.FdParser;

public class FdParserTest {
	@Test
	public void testExecFd() {
		var funcTable = FdParser.readFdFile("data/fd/exec_lib.fd");
		assertEquals(147, funcTable.getFunctions().length);
	}

	@Test
	public void testExecSfd() {
		var funcTable = FdParser.readSfdFile("data/sfd/exec_lib.sfd");
		assertEquals(125, funcTable.getFunctions().length);
		var func = funcTable.getFunctionByName("AVL_FindNextNodeByKey");
		assertNotNull(func);
		assertEquals("exec_library", func.getLib());
		assertEquals(-0x37e, func.getBias());
		assertEquals(3, func.getArgs().size());

		assertEquals("root", func.getArgs().get(0).name);
		assertEquals("CONST struct AVLNode *", func.getArgs().get(0).type);
		assertEquals("a0", func.getArgs().get(0).reg);

		assertEquals("key", func.getArgs().get(1).name);
		assertEquals("APTR", func.getArgs().get(1).type);
		assertEquals("a1", func.getArgs().get(1).reg);

		assertEquals("func", func.getArgs().get(2).name);
		assertEquals("APTR", func.getArgs().get(2).type);
		assertEquals("a2", func.getArgs().get(2).reg);
	}

	@Test
	public void testAllSfd() {
		File dir = new File("data/sfd");
		for(var entry : dir.listFiles()) {
			var funcTable = FdParser.readSfdFile(entry.getPath());
			assertNotNull(entry.getPath(), funcTable);
		}
	}
}
