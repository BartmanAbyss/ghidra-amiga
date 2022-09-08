package structs;

public class CustomChipRegisters {
	enum Register {
		BLTDDAT(RegType.Word), DMACONR(RegType.Word), VPOSR(RegType.Word), VHPOSR(RegType.Word), DSKDATR(RegType.Word),
		JOY0DAT(RegType.Word), JOT1DAT(RegType.Word), CLXDAT(RegType.Word), AKCONR(RegType.Word), POT0DAT(RegType.Word),
		POT1DAT(RegType.Word), POTGOR(RegType.Word), SERDATR(RegType.Word), DSKBYTR(RegType.Word),
		INTENAR(RegType.Word), INTREQR(RegType.Word), DSKPT(RegType.DWord), DSKLEN(RegType.Word), DSKDAT(RegType.Word),
		REFPTR(RegType.Word), VPOSW(RegType.Word), VHPOSW(RegType.Word), COPCON(RegType.Word), SERDAT(RegType.Word),
		SERPER(RegType.Word), POTGO(RegType.Word), JOYTEST(RegType.Word), STREQU(RegType.Word), STRVBL(RegType.Word),
		STRHOR(RegType.Word), STRLONG(RegType.Word), BLTCON0(RegType.Word), BLTCON1(RegType.Word),
		BLTAFWM(RegType.Word), BLTALWM(RegType.Word), BLTCPT(RegType.Addr), BLTBPT(RegType.Addr), BLTAPT(RegType.Addr),
		BLTDPT(RegType.Addr), BLTSIZE(RegType.Word), BLTCON0L(RegType.Word), BLTSIZV(RegType.Word),
		BLTSIZH(RegType.Word), BLTCMOD(RegType.Word), BLTBMOD(RegType.Word), BLTAMOD(RegType.Word),
		BLTDMOD(RegType.Word), RESERVED1(RegType.Word), RESERVED2(RegType.Word), RESERVED3(RegType.Word),
		RESERVED4(RegType.Word), BLTCDAT(RegType.Word), BLTBDAT(RegType.Word), BLTADAT(RegType.Word),
		RESERVED5(RegType.Word), SPRHDAT(RegType.Word), BPLHDAT(RegType.Word), LISAID(RegType.Word),
		DSKSYNC(RegType.Word), COP1LC(RegType.Addr), COP2LC(RegType.Addr), COPJMP1(RegType.Word), COPJMP2(RegType.Word),
		COPINS(RegType.Word), DIWSTRT(RegType.Word), DIWSTOP(RegType.Word), DDFSTRT(RegType.Word),
		DDFSTOP(RegType.Word), DMACON(RegType.Word), CLXCON(RegType.Word), INTENA(RegType.Word), INTREQ(RegType.Word),
		ADKCON(RegType.Word), AUD0LC(RegType.Addr), AUD0LEN(RegType.Word), AUD0PER(RegType.Word), AUD0VOL(RegType.Word),
		AUD0DAT(RegType.Word), RESERVED6(RegType.Word), RESERVED7(RegType.Word), AUD1LC(RegType.Addr),
		AUD1LEN(RegType.Word), AUD1PER(RegType.Word), AUD1VOL(RegType.Word), AUD1DAT(RegType.Word),
		RESERVED8(RegType.Word), RESERVED9(RegType.Word), AUD2LC(RegType.Addr), AUD2LEN(RegType.Word),
		AUD2PER(RegType.Word), AUD2VOL(RegType.Word), AUD2DAT(RegType.Word), RESERVED10(RegType.Word),
		RESERVED11(RegType.Word), AUD3LC(RegType.Addr), AUD3LEN(RegType.Word), AUD3PER(RegType.Word),
		AUD3VOL(RegType.Word), AUD3DAT(RegType.Word), RESERVED12(RegType.Word), RESERVED13(RegType.Word),
		BPL1PT(RegType.Addr), BPL2PT(RegType.Addr), BPL3PT(RegType.Addr), BPL4PT(RegType.Addr), BPL5PT(RegType.Addr),
		BPL6PT(RegType.Addr), BPL7PT(RegType.Addr), BPL8PT(RegType.Addr), BPLCON0(RegType.Word), BPLCON1(RegType.Word),
		BPLCON2(RegType.Word), BPLCON3(RegType.Word), BPL1MOD(RegType.Word), BPL2MOD(RegType.Word),
		BPLCON4(RegType.Word), CLXCON2(RegType.Word), BPL1DAT(RegType.Word), BPL2DAT(RegType.Word),
		BPL3DAT(RegType.Word), BPL4DAT(RegType.Word), BPL5DAT(RegType.Word), BPL6DAT(RegType.Word),
		BPL7DAT(RegType.Word), BPL8DAT(RegType.Word), SPR0PT(RegType.Addr), SPR1PT(RegType.Addr), SPR2PT(RegType.Addr),
		SPR3PT(RegType.Addr), SPR4PT(RegType.Addr), SPR5PT(RegType.Addr), SPR6PT(RegType.Addr), SPR7PT(RegType.Addr),
		SPR0POS(RegType.Word), SPR0CTL(RegType.Word), SPR0DATA(RegType.Word), SPR0DATB(RegType.Word),
		SPR1POS(RegType.Word), SPR1CTL(RegType.Word), SPR1DATA(RegType.Word), SPR1DATB(RegType.Word),
		SPR2POS(RegType.Word), SPR2CTL(RegType.Word), SPR2DATA(RegType.Word), SPR2DATB(RegType.Word),
		SPR3POS(RegType.Word), SPR3CTL(RegType.Word), SPR3DATA(RegType.Word), SPR3DATB(RegType.Word),
		SPR4POS(RegType.Word), SPR4CTL(RegType.Word), SPR4DATA(RegType.Word), SPR4DATB(RegType.Word),
		SPR5POS(RegType.Word), SPR5CTL(RegType.Word), SPR5DATA(RegType.Word), SPR5DATB(RegType.Word),
		SPR6POS(RegType.Word), SPR6CTL(RegType.Word), SPR6DATA(RegType.Word), SPR6DATB(RegType.Word),
		SPR7POS(RegType.Word), SPR7CTL(RegType.Word), SPR7DATA(RegType.Word), SPR7DATB(RegType.Word),
		COLOR00(RegType.Word), COLOR01(RegType.Word), COLOR02(RegType.Word), COLOR03(RegType.Word), 
		COLOR04(RegType.Word), COLOR05(RegType.Word), COLOR06(RegType.Word), COLOR07(RegType.Word), 
		COLOR08(RegType.Word), COLOR09(RegType.Word), COLOR10(RegType.Word), COLOR11(RegType.Word), 
		COLOR12(RegType.Word), COLOR13(RegType.Word), COLOR14(RegType.Word), COLOR15(RegType.Word), 
		COLOR16(RegType.Word), COLOR17(RegType.Word), COLOR18(RegType.Word), COLOR19(RegType.Word), 
		COLOR20(RegType.Word), COLOR21(RegType.Word), COLOR22(RegType.Word), COLOR23(RegType.Word), 
		COLOR24(RegType.Word), COLOR25(RegType.Word), COLOR26(RegType.Word), COLOR27(RegType.Word), 
		COLOR28(RegType.Word), COLOR29(RegType.Word), COLOR30(RegType.Word), COLOR31(RegType.Word), 
		HTOTAL(RegType.Word), HSSTOP(RegType.Word), HBSTRT(RegType.Word), HBSTOP(RegType.Word),
		VTOTAL(RegType.Word), VSSTOP(RegType.Word), VBSTRT(RegType.Word), VBSTOP(RegType.Word), SPRHSTRT(RegType.Word),
		SPRHSTOP(RegType.Word), BPLHSTRT(RegType.Word), BPLHSTOP(RegType.Word), HHPOSW(RegType.Word),
		HHPOSR(RegType.Word), BEAMCON0(RegType.Word), HSSTRT(RegType.Word), VSSTRT(RegType.Word), HCENTER(RegType.Word),
		DIWHIGH(RegType.Word), BPLHMOD(RegType.Word), SPRHPT(RegType.Addr), BPLHPT(RegType.Addr),
		RESERVED14(RegType.Word), RESERVED15(RegType.Word), RESERVED16(RegType.Word), RESERVED17(RegType.Word),
		RESERVED18(RegType.Word), RESERVED19(RegType.Word), FMODE(RegType.Word), NOOP(RegType.Word);

		public RegType type;

		Register(RegType type) {
			this.type = type;
		}

		public boolean pair() {
			return this.type != RegType.Word;
		}
	}

	enum RegType {
		Word, DWord, Addr,
	}

	public static Register[] registerByIndex;
	static {
		registerByIndex = new Register[256];
		int i = 0;
		for (Register reg : Register.values()) {
			int length = 0;
			switch (reg.type) {
				case Word:
					length = 1;
					break;
				case DWord:
				case Addr:
					length = 2;
					break;
			}
			int stop = i + length;
			for (; i < stop; i++) {
				registerByIndex[i] = reg;
			}
		}
	}
}