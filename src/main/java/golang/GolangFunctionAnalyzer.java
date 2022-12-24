/**
 * 
 */
package golang;
import java.util.ArrayList;
import ghidra.util.DefaultErrorLogger;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.Analyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.HelpLocation;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * @author kaida
 *
 */
public class GolangFunctionAnalyzer implements Analyzer {

	@Override
	public String getName() {
		return "Golang Functions";
	}

	@Override
	public AnalyzerType getAnalysisType() {
		return AnalyzerType.BYTE_ANALYZER;
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return true;
	}

	@Override
	public boolean supportsOneTimeAnalysis() {
		return true;
	}

	@Override
	public String getDescription() {
		return "Parse the Golang compiler output to identify functions and their details";
	}

	@Override
	public AnalysisPriority getPriority() {
		return AnalysisPriority.FORMAT_ANALYSIS;
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getCompilerSpec().getCompilerSpecID().getIdAsString().equals("golang");
	}

	private DataType findFirstDataType(Program program, String name) throws Exception {
		ArrayList<DataType> type_list = new ArrayList<>();
		program.getDataTypeManager().findDataTypes(name, type_list);
		if (type_list.size() == 0) {
			throw new Exception("DataType could not be found. Is the data type defined in your program's DataTypes?");
		}
		
		return type_list.get(0);
	}

	private DataType getGolangPclntabMagicEnumDataType(Program program) throws Exception {
		String type_name = "GolangPclntabMagic";
		CategoryPath golang_category_path = new CategoryPath(CategoryPath.ROOT, "Golang");
		DataType golang_pclntab_magic = program.getDataTypeManager().getDataType(golang_category_path.extend(type_name).getPath());
		if (golang_pclntab_magic == null) {
			Category golang_category = program.getDataTypeManager().createCategory(golang_category_path);
			EnumDataType golang_pclntab_magic_enum = new EnumDataType(golang_category.getCategoryPath(), type_name, 4);
			golang_pclntab_magic_enum.add("PCLNTAB_v0", 0xFFFFFFF0, "Set in commit: https://github.com/golang/go/commit/d3ad216f8e7ea7699fe44990c65213c26aba907d");
			golang_pclntab_magic_enum.add("PCLNTAB_v1", 0xFFFFFFF1, "Set in commit: https://github.com/golang/go/commit/0f8dffd0aa71ed996d32e77701ac5ec0bc7cde01");

			golang_pclntab_magic = program.getDataTypeManager().addDataType(golang_pclntab_magic_enum, DataTypeConflictHandler.KEEP_HANDLER);
		}
		return golang_pclntab_magic;
	}

	private DataType getGolangPcheaderStructureDataType(Program program) throws Exception {
		CategoryPath golang_category_path = new CategoryPath(CategoryPath.ROOT, "Golang");
		DataType golang_pcheader = program.getDataTypeManager().getDataType("/Golang/GolangPcheaderV0");
		if (golang_pcheader == null ) {
			Category golang_category = program.getDataTypeManager().createCategory(golang_category_path);

			DataType uint8_t = this.findFirstDataType(program, "char"); // For the moment this is a char, but it should really be a uint8_t
			ByteDataType byte_datatype = new ByteDataType();
			IntegerDataType int_datatype = new IntegerDataType();
			UnsignedIntegerDataType uint_datatype = new UnsignedIntegerDataType();


			// TODO: Use the right pointer data type
			DataType generic_pointer = this.findFirstDataType(program, "void *");
			//DataType uint32_t = this.findFirstDataType(program, "uint32_t");
			//DataType uintptr_t = this.findFirstDataType(program, "uintptr_t");

			StructureDataType golang_pcheader_struct = new StructureDataType(
					golang_category_path,
					"GolangPcheaderV0",
					0
			);
			DataType magic_data_type = this.getGolangPclntabMagicEnumDataType(program);
			golang_pcheader_struct.add(magic_data_type, magic_data_type.getLength(), "magic", "The pclntab magic, as defined in src/runtime/symtab.go");
			golang_pcheader_struct.add(uint8_t, uint8_t.getLength(), "pad0", "First padding byte");
			golang_pcheader_struct.add(uint8_t, uint8_t.getLength(), "pad1", "Second padding byte");
			golang_pcheader_struct.add(byte_datatype, byte_datatype.getLength(), "minLC", "min instruction size");
			golang_pcheader_struct.add(byte_datatype, byte_datatype.getLength(), "ptrSize", "size of a ptr in bytes");
			// TODO: Validate if our analysis is correct, compare the ptrSize to what Ghidra thinks the pointer size is
			golang_pcheader_struct.add(int_datatype, int_datatype.getLength(), "nfunc", "number of functions in the module");
			golang_pcheader_struct.add(uint_datatype, uint_datatype.getLength(), "nfiles", "number of entries in the file tab");
			golang_pcheader_struct.add(uint_datatype, uint_datatype.getLength(), "textStart", "base for function entry PC offsets in this module, equal to moduledata.text");
			golang_pcheader_struct.add(uint_datatype, uint_datatype.getLength(), "funcnameOffset", "offset to the funcnametab variable from pcHeader");
			golang_pcheader_struct.add(uint_datatype, uint_datatype.getLength(), "cuOffset", "offset to the cutab variable from pcHeader");
			golang_pcheader_struct.add(uint_datatype, uint_datatype.getLength(), "filetabOffset", "offset to the filetab variable from pcHeader");
			golang_pcheader_struct.add(uint_datatype, uint_datatype.getLength(), "pctabOffset", "offset to the pctab variable from pcHeader");
			golang_pcheader_struct.add(uint_datatype, uint_datatype.getLength(), "pclnOffset", "offset to the pclntab variable from pcHeader");

			golang_pcheader = program.getDataTypeManager().addDataType(golang_pcheader_struct, DataTypeConflictHandler.KEEP_HANDLER);
		}
		return golang_pcheader;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
			try {
				getGolangPclntabMagicEnumDataType(program);
				DataType pcheader_struct = getGolangPcheaderStructureDataType(program);
				Symbol runtime_pclntab = program.getSymbolTable().getSymbols("_runtime.pclntab").next();
				Address pcheader_address = runtime_pclntab.getAddress();
				Data pclntab = program.getListing().createData(pcheader_address, pcheader_struct);
			} catch (Exception e) {
				// do nothing because we are bad
				log.appendMsg(getName(), "Failed to create DataTypes");
				log.appendException(e);
				throw new CancelledException("Failed to create DataTypes");
			}
			return true;
	}

	@Override
	public boolean removed(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		return false;
	}

	@Override
	public void registerOptions(Options options, Program program) {
	}

	@Override
	public void optionsChanged(Options options, Program program) {
	}

	@Override
	public void analysisEnded(Program program) {
		// TODO Auto-generated method stub

	}

	@Override
	public boolean isPrototype() {
		// TODO This is very beta ;)
		return true;
	}

}
