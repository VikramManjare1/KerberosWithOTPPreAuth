package kpa;

/**
 * @author Windows Vikram Manjare (CS20M070 IITM 2021) 23-Aug-2021
 * 
 *         Utility class for displaying debug trace properly in console
 */
public class Display {
	private static enum LineType {
		SOLID {
			public String toString() {
				return "_";
			}
		},

		DASHED {
			public String toString() {
				return "-";
			}
		},

		STAR {
			public String toString() {
				return "*";
			}
		}
	}

	public static void printSolidLine() {
		printLine(LineType.SOLID);
	}

	public static void printDashedLine() {
		printLine(LineType.DASHED);
	}

	public static void printStarLine() {
		printLine(LineType.STAR);
	}
	
	public static void printSolidLineShort() {
		printLineShort(LineType.SOLID);
	}

	public static void printDashedLineShort() {
		printLineShort(LineType.DASHED);
	}

	public static void printStarLineShort() {
		printLineShort(LineType.STAR);
	}

	private static void printLine(LineType lineType) {
		for (int i = 0; i < 80; i++) {
			System.out.print(lineType);
		}
		System.out.println();
	}
	
	private static void printLineShort(LineType lineType) {
		for (int i = 0; i < 40; i++) {
			System.out.print(lineType);
		}
		System.out.println();
	}
}
