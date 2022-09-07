package fd;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;

import ghidra.framework.Application;

public class FdParser {
	public static final String EXEC_LIB = "exec_library";
	public static final String DOS_LIB = "dos_library";
	private static final Pattern FUNC_PAT = Pattern.compile("([A-Za-z][_A-Za-z00-9]+)\\((.*?)\\)(?:\\((.*?)\\))?");

	public static FdLibFunctions readFdFile(String libName) {
		try {
			File f = new File(libName);

			if(!f.exists()) {
				f = new File("fd", libName);
				f = Application.getModuleDataFile(f.getPath()).getFile(false);

				if(!f.exists()) {
					return null;
				}
			}

			return readFd(f);
		} catch(Exception e) {
			return null;
		}
	}

	public static FdLibFunctions readSfdFile(String libName) {
		try {
			File f = new File(libName);

			if(!f.exists()) {
				f = new File("sfd", libName);
				f = Application.getModuleDataFile(f.getPath()).getFile(false);

				if(!f.exists()) {
					return null;
				}
			}

			return readSfd(f);
		} catch(Exception e) {
			return null;
		}
	}

	private static FdLibFunctions readFd(File f) throws Exception {
		FdLibFunctions funcTable = null;

		int bias = 0;
		boolean privat = true;

		BufferedReader reader;
		List<String> lines = new ArrayList<String>();

		reader = new BufferedReader(new FileReader(f));
		String _line = reader.readLine();
		while(_line != null) {
			lines.add(_line);
			_line = reader.readLine();
		}
		reader.close();

		for(String line : lines) {
			line = line.strip();

			if(line.length() > 1 && line.charAt(0) != '*') {
				// command
				if(line.charAt(0) == '#' && line.charAt(1) == '#') {
					String cmdLine = line.substring(2);
					String[] cmda = cmdLine.split(" ");
					String cmd = cmda[0];

					if(cmd.equals("base")) {
						funcTable = new FdLibFunctions(cmda[1]);
					} else if(cmd.equals("bias")) {
						bias = -1 * Integer.parseInt(cmda[1]);
					} else if(cmd.equals("private")) {
						privat = true;
					} else if(cmd.equals("public")) {
						privat = false;
					} else if(cmd.equals("end")) {
						break;
					} else {
						return null;
					}
				} else {
					Matcher m = FUNC_PAT.matcher(line);

					if(!m.matches()) {
						throw new Exception("Invalid FD format!");
					}

					String name = m.group(1);

					FdFunction func = new FdFunction(f.getName().toLowerCase(), name, null, bias, privat);

					if(func != null) {
						funcTable.addFunction(func);
					}

					String args = m.group(2);
					String regs = m.group(3) != null ? m.group(3) : "";

					String[] arg = args.replaceAll(",", "/").split("/");
					String[] reg = regs.replaceAll(",", "/").split("/");

					if(arg.length != reg.length) {
						if(arg.length * 2 == reg.length) {
							arg = new String[reg.length];
							String[] argHi = (String[]) Arrays.asList(arg).stream()
									.map(e -> e + "_hi")
									.toArray();
							String[] argLo = (String[]) Arrays.asList(arg).stream()
									.map(e -> e + "_lo")
									.toArray();

							for(int i = 0; i < arg.length; i += 2) {
								arg[i] = argHi[i / 2];
								arg[i + 1] = argLo[i / 2];
							}
						} else {
							throw new Exception("Reg and Arg name mismatch in FD file!");
						}
					}

					if(!arg[0].isEmpty()) {
						for(int i = 0; i < arg.length; ++i) {
							func.addArg(arg[i], null, reg[i].toUpperCase());
						}
					}

					bias -= 6;
				}
			}
		}

		return funcTable;
	}

	private static FdLibFunctions readSfd(File f) throws Exception {
		FdLibFunctions funcTable = null;
		var libname = f.getName();
		libname = libname.substring(0, libname.lastIndexOf('.')); // fallback for cia_lib.sfd

		BufferedReader reader;
		var lines = new ArrayList<String>();

		reader = new BufferedReader(new FileReader(f));
		String tempLine;
		while((tempLine = reader.readLine()) != null) {
			if(tempLine.startsWith("\t"))
				lines.set(lines.size() - 1, lines.get(lines.size() - 1) + tempLine.substring(1));
			else
				lines.add(tempLine);
		}
		reader.close();

		int offset = 0;
		boolean isAlias = false, isVarargs = false;
		for(var line : lines) {
			if(line.startsWith("==")) {
				if(line.startsWith("libname", 2))
					libname = line.substring(2 + "libname".length() + 1).replace('.', '_');
				if(line.startsWith("bias", 2))
					offset = -Integer.parseInt(line.substring(2 + "bias".length() + 1));
				else if(line.startsWith("reserve", 2))
					offset -= Integer.parseInt(line.substring(2 + "reserve".length() + 1)) * 6;
				else if(line.startsWith("varargs", 2))
					isVarargs = true;
				else if(line.startsWith("alias", 2))
					isAlias = true;
				else if(line.startsWith("end", 2))
					break;
			} else {
				if(isAlias)
					offset += 6;
				if(funcTable == null)
					funcTable = new FdLibFunctions(libname);
				var paren_arg = line.indexOf('(');
				var paren_reg = line.lastIndexOf('(');
				assert paren_arg != -1;
				assert paren_reg != -1;
				var func_spc = line.lastIndexOf(' ', paren_arg);
				assert func_spc != -1;
				var func = new FdFunction(libname, line.substring(func_spc + 1, paren_arg), line.substring(0, func_spc), offset, false);

				var p_arg = paren_arg + 1;
				var p_reg = paren_reg + 1;
				for(;;) {
					String reg = null;
					String name;
					String type;

					var next_reg = StringUtils.indexOfAny(line.substring(p_reg), ",)");
					if(next_reg != -1) {
						// may run out of registers with va_list (...)
						reg = line.substring(p_reg, next_reg + p_reg);
						p_reg = next_reg + p_reg + 1;
					}
	
					var next = StringUtils.indexOfAny(line.substring(p_arg), "(),") + p_arg;
					assert next >= p_arg && next < paren_reg;
					if(line.charAt(next) == ',' || line.charAt(next) == ')') {
						var arg_spc = line.lastIndexOf(' ', next);
						assert arg_spc != -1;
						if(arg_spc > p_arg) {
							type = line.substring(p_arg, arg_spc);
							name = line.substring(arg_spc + 1, next);
							func.addArg(name, type, reg);
						}
	
						if(line.charAt(next) == ')') // end of args
							break;
	
						p_arg = next + 1; // next arg
					} else if(line.charAt(next) == '(') {
						// function pointer
						assert line.charAt(next + 1) == '*';
						var funcptr_paren = line.indexOf(')', next + 2);
						assert funcptr_paren != -1;
	
						var func_end = line.indexOf(')', funcptr_paren + 1);
						assert func_end != -1;
	
						name = line.substring(next + 2, funcptr_paren);
						type = line.substring(p_arg, next + 2) + line.substring(funcptr_paren, func_end + 1);
						func.addArg(name, type, reg);
	
						if(line.charAt(func_end + 1) == ')') // end of args
							break;
	
						assert line.charAt(func_end + 1) == ',';
						p_arg = func_end + 2;
					}
					if(line.charAt(p_arg) == ' ') p_arg++;
				}
				//System.out.format("%s returns '%s' = -$%x\n", func.getName(false), func.getReturnType(), Math.abs(func.getBias()));
				//for(var arg : func.getArgs())
				//	System.out.format("\t'%s' '%s' (%s)\n", arg.name, arg.type, arg.reg);
				if(!isAlias)
					funcTable.addFunction(func);
				isVarargs = false;
				isAlias = false;
				offset -= 6;
			}
		}

		return funcTable;
	}
}
