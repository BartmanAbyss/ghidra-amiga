package fd;

import java.util.ArrayList;
import java.util.stream.Collectors;

import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;

public class FdFunction {
	private final String lib;
	private final String name;
	private final String returnType;
	private final int bias;
	private final boolean privat;
	private final int index;
	
	public class Arg {
		public Arg(String name, String type, String reg) {
			this.name = name;
			this.type = type;
			this.reg = reg;
		}
		public String name;
		public String type;
		public String reg;
	}

	private ArrayList<Arg> args;
	
	public static final String LIB_SPLITTER = "->";
	
	public FdFunction(String lib, String name, String returnType, int bias, boolean privat) {
		this.lib = lib;
		this.name = name;
		this.returnType = returnType;
		this.bias = bias;
		this.index = (bias - 6) / 6;
		this.privat = privat;
		
		args = new ArrayList<>();
	}
	
	public final String getLib() {
		return lib;
	}

	public final String getName(boolean withLib) {
		return (withLib ? lib + LIB_SPLITTER : "") + name;
	}

	public final String getReturnType() {
		return returnType;
	}

	public final int getBias() {
		return bias;
	}
	
	public final int getIndex() {
		return index;
	}

	public final boolean isPrivate() {
		return privat;
	}
	
	public ArrayList<Arg> getArgs() {
		return args;
	}
	
	public void addArg(String name, String type, String reg) {
		name = name.replace(" ", "").replace("*", "");
		
		args.add(new Arg(name, type, reg));
	}
	
	public String getArgsStr(boolean withReg) {
		if (args.size() == 0) {
			return "";
		} else {
			StringBuilder sb = new StringBuilder();
			sb.append("( ");
			
			if (withReg) {
				sb.append(args.stream()
					.map(e -> e.name + "/" + e.reg)
					.collect(Collectors.joining(", ")));
			} else {
				sb.append(args.stream()
					.map(e-> e.name)
					.collect(Collectors.joining(", ")));
			}
			
			sb.append(" )");
			return sb.toString();
		}
	}
	
	public Register[] getArgRegs(Program program) {
		if (args.size() == 0) {
			return new Register[] {};
		} else {
			return args.stream()
				.map(e -> new Register(program.getRegister(e.reg))).toArray(Register[]::new);
		}
	}
}
