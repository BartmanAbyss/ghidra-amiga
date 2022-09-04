package amigahunk;

import static org.junit.Assert.assertEquals;
import org.junit.Test;

public class FdParserTest {
	@Test
	public void test1() {
		var funcTable = FdParser.readFdFile("data/fd/exec_lib.fd");
		assertEquals(147, funcTable.getFunctions().length);
	}
}
