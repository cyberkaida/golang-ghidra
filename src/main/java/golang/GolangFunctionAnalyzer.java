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
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TerminatedStringDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBufferImpl;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.HelpLocation;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.exception.NotYetImplementedException;
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
			throw new Exception("DataType " + name + " could not be found. Is the data type defined in your program's DataTypes?");
		}
		
		return type_list.get(0);
	}

	private DataType getGolangSliceDataType(Program program) throws Exception {
		String type_name = "GolangSlice";
		CategoryPath golang_category_path = new CategoryPath(CategoryPath.ROOT, "Golang");
		DataType golang_slice = program.getDataTypeManager().getDataType(golang_category_path.extend(type_name).getPath());
		if (golang_slice == null) {
			Category golang_category = program.getDataTypeManager().createCategory(golang_category_path);
			DataType pointer = new PointerDataType(new VoidDataType());
			LongLongDataType integer = new LongLongDataType();

			StructureDataType golang_slice_struct = new StructureDataType(
					golang_category_path,
					type_name,
					0 // 0 so Ghidra calculates from fields
			);

			// TODO: Maybe go to the array pointer and create the correctly size array
			// The generic pointer should point to this location and Ghidra should figure the rest out
			golang_slice_struct.add(pointer, pointer.getLength(), "array", "Pointer to the first element of the slice content");
			golang_slice_struct.add(integer, integer.getLength(), "len", "Length of the array");
			golang_slice_struct.add(integer, integer.getLength(), "cap", "The initial capacity of the Golang slice");
			golang_slice_struct.setToDefaultPacking();

			golang_slice = program.getDataTypeManager().addDataType(golang_slice_struct, DataTypeConflictHandler.KEEP_HANDLER);

		}
		return golang_slice;
	}

	private Data createGolangSlice(Program program, Address slice_address, DataType slice_type) throws Exception {
		Data existing_data = program.getListing().getDataContaining(slice_address);
		if (existing_data == null) {
			program.getListing().createData(slice_address, getGolangSliceDataType(program));
		}

		PointerDataType content = new PointerDataType(slice_type, program.getDataTypeManager());
		LongLongDataType size = new LongLongDataType();

		MemoryBufferImpl content_address_buffer = new MemoryBufferImpl(program.getMemory(), slice_address, content.getLength());
		Address content_address = PointerDataType.getAddressValue(content_address_buffer, content.getLength(), content.getDefaultSettings());

		MemoryBufferImpl size_buffer = new MemoryBufferImpl(program.getMemory(), slice_address.add(content.getLength()), size.getLength());
		long content_array_size = ((Scalar)size.getValue(size_buffer, size.getDefaultSettings(), size.getLength())).getValue();
		

		// TODO: This will truncate large arrays, but these are very large
		ArrayDataType content_array = new ArrayDataType(slice_type, (int)content_array_size, slice_type.getLength());
		program.getListing().clearCodeUnits(content_address, content_address.add(content_array.getLength()), true);
		Data new_data = program.getListing().createData(content_address, content_array);
		return new_data;
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

	private DataType getGolangFunctabStructDataType(Program program) throws Exception {
		String type_name = "GolangFunctab";
		CategoryPath golang_category_path = new CategoryPath(CategoryPath.ROOT, "Golang");
		DataType golang_functab_type = program.getDataTypeManager().getDataType(golang_category_path.extend(type_name).getPath());
		if (golang_functab_type == null) {
			UnsignedIntegerDataType uint32_t = new UnsignedIntegerDataType(program.getDataTypeManager());

			StructureDataType golang_functab_struct = new StructureDataType(
					golang_category_path,
					type_name,
					0 // 0 so Ghidra calculates from fields
			);

			// TODO: Confirm these offsets
			golang_functab_struct.add(uint32_t, uint32_t.getLength(), "entryoff", "The offset to the entry relative to runtime.text");
			golang_functab_struct.add(uint32_t, uint32_t.getLength(), "funcoff", "The offset to the function relative to runtime.text");
			golang_functab_struct.setToDefaultPacking();

			golang_functab_type = program.getDataTypeManager().addDataType(golang_functab_struct, DataTypeConflictHandler.KEEP_HANDLER);
		}

		return golang_functab_type;	
	}

	private Data createGolangModuleStructure(Program program, Address module_address) throws Exception {
		// https://github.com/golang/go/blob/5639fcae7fee2cf04c1b87e9a81155ee3bb6ed71/src/runtime/symtab.go#L415
		CategoryPath golang_category_path = new CategoryPath(CategoryPath.ROOT, "Golang");
		DataType golang_moduleinfo_type = program.getDataTypeManager().getDataType("/Golang/GolangModuleInfo");

		DataType uint32_t = new IntegerDataType(program.getDataTypeManager());

		Category golang_category = program.getDataTypeManager().createCategory(golang_category_path);
		DataType golang_pcheader_pointer = new PointerDataType(getGolangPcheaderStructureDataType(program));
		DataType golang_slice = getGolangSliceDataType(program);

		StructureDataType golang_moduleinfo_struct = new StructureDataType(
				golang_category_path,
				"GolangModuleInfo",
				0 // 0 so Ghidra calculates from fields
		);

		golang_moduleinfo_struct.add(golang_pcheader_pointer, golang_pcheader_pointer.getLength(), "pcHeader", "Pointer to the pcHeader structure");
		golang_moduleinfo_struct.add(golang_slice, golang_slice.getLength(), "funcnametab", "Slice of function names");
		golang_moduleinfo_struct.add(golang_slice, golang_slice.getLength(), "cutab", "Slice of cutab?");
		golang_moduleinfo_struct.add(golang_slice, golang_slice.getLength(), "filetab", "The filetable");
		golang_moduleinfo_struct.add(golang_slice, golang_slice.getLength(), "pctab", "The program counter table");
		golang_moduleinfo_struct.add(golang_slice, golang_slice.getLength(), "pclntab", "The program counter linkage table");
		golang_moduleinfo_struct.add(golang_slice, golang_slice.getLength(), "ftab", "Function table slice");
		// TODO: Implement the rest of this structure

		golang_moduleinfo_struct.setToDefaultPacking();
		golang_moduleinfo_type = program.getDataTypeManager().addDataType(golang_moduleinfo_struct, DataTypeConflictHandler.REPLACE_HANDLER);


		// Clear any existing data, we will replace this with our structure
		program.getListing().clearCodeUnits(module_address, module_address.add(golang_moduleinfo_type.getLength()), true);
		Data golang_moduleinfo = program.getListing().createData(module_address, golang_moduleinfo_type);

		// TODO: Make this a buffer of TerminatedStringDataType
		createGolangSlice(
				program,
				golang_moduleinfo.getComponent(1).getAddress(),
				new ByteDataType()
				);

		createGolangSlice(
				program,
				golang_moduleinfo.getComponent(2).getAddress(),
				uint32_t
				);

		createGolangSlice(
				program,
				golang_moduleinfo.getComponent(3).getAddress(),
				new ByteDataType()
				);

		createGolangSlice(
				program,
				golang_moduleinfo.getComponent(4).getAddress(),
				new ByteDataType()
				);

		createGolangSlice(
				program,
				golang_moduleinfo.getComponent(5).getAddress(),
				new ByteDataType()
				);

		createGolangSlice(
				program,
				golang_moduleinfo.getComponent(6).getAddress(),
				getGolangFunctabStructDataType(program)
				);

		return golang_moduleinfo;
	}

	private DataType getGolangPcheaderStructureDataType(Program program) throws Exception {
		CategoryPath golang_category_path = new CategoryPath(CategoryPath.ROOT, "Golang");
		DataType golang_pcheader = program.getDataTypeManager().getDataType("/Golang/GolangPcheaderV0");
		if (golang_pcheader == null ) {
			Category golang_category = program.getDataTypeManager().createCategory(golang_category_path);

			ByteDataType byte_datatype = new ByteDataType();
			IntegerDataType int_datatype = new IntegerDataType();
			UnsignedIntegerDataType uint_datatype = new UnsignedIntegerDataType();

			// TODO: Use the right pointer data type
			DataType generic_pointer = new PointerDataType();

			StructureDataType golang_pcheader_struct = new StructureDataType(
					golang_category_path,
					"GolangPcheaderV0",
					0
			);
			// Now let us fill in the structure
			// This structure is part of the go compiler output. The magic changes with Golang compiler versions.
			// This method implements the following:
			// https://github.com/golang/go/blob/5639fcae7fee2cf04c1b87e9a81155ee3bb6ed71/src/runtime/symtab.go#L395
			// https://github.com/golang/go/blob/f2656f20ea420ada5f15ef06ddf18d2797e18841/src/runtime/symtab.go#L407
			DataType magic_data_type = this.getGolangPclntabMagicEnumDataType(program);
			golang_pcheader_struct.add(magic_data_type, magic_data_type.getLength(), "magic", "The pclntab magic, as defined in src/runtime/symtab.go");
			golang_pcheader_struct.add(byte_datatype, byte_datatype.getLength(), "pad0", "First padding byte");
			golang_pcheader_struct.add(byte_datatype, byte_datatype.getLength(), "pad1", "Second padding byte");
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
				FlatProgramAPI api = new FlatProgramAPI(program, monitor);
				// Parse the pcheader structure
				monitor.setMessage("Parsing Golang pcheader");
				// We can use this to choose the appropriate version of the pcheader structure to apply
				DataType pcheader_magic_datatype = getGolangPclntabMagicEnumDataType(program);

				DataType pcheader_struct = this.getGolangPcheaderStructureDataType(program); 
				Symbol runtime_pclntab = program.getSymbolTable().getSymbols("_runtime.pclntab").next();
				Address pcheader_address = runtime_pclntab.getAddress();
				Data existing_pcheader_data = program.getListing().getDataAt(pcheader_address);

				if (existing_pcheader_data != null) {
					log.appendMsg("Data already exist at pcheader location. Clearing to make room for the pcheader");
					api.clearListing(pcheader_address, pcheader_address.add(pcheader_struct.getLength()));
				}

				// Extract the values from the structure and add xrefs to discover things and allow
				// other analysis modules to use these to find things like functions and strings.
				Data pcheader = program.getListing().createData(pcheader_address, pcheader_struct);
				// TODO: Iterate over the components and find the correct field
				Scalar text_start_field_value = (Scalar) pcheader.getComponent(7).getValue();
				Address text_start_field_address = pcheader.getComponent(7).getAddress();
				Address text_start_address = pcheader.getAddress().add(text_start_field_value.getValue());

				program.getReferenceManager().addMemoryReference(text_start_field_address, text_start_address, RefType.DATA, SourceType.ANALYSIS, 0);

				// Parse the module info table
				Symbol first_module_info = program.getSymbolTable().getSymbols("_runtime.firstmoduledata").next();
				Address first_module_address = first_module_info.getAddress();
				createGolangModuleStructure(program, first_module_address);
				getGolangSliceDataType(program);

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
