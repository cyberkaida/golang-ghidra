package golang;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.BooleanDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.ShortDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBufferImpl;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.NotYetImplementedException;

public class GolangTypes {
	Program program = null;
	DataTypeManager data_type_manager = null;
	CategoryPath golang_category_path = null;

	GolangTypes(Program program) {
		this.program = program;
		data_type_manager = this.program.getDataTypeManager();
		golang_category_path = new CategoryPath(CategoryPath.ROOT, "Golang");
	}

	public boolean isGo() {
		boolean is_go = false;
		// src/cmd/go/internal/version/exe.go
		if (program.getMemory().getBlock("__go_buildinfo") != null) {
			is_go = true;
		}

		if (program.getMemory().getBlock("__go_pclntab") != null) {
			is_go = true;
		}

		// For Windows
		MemoryBlock text_block = program.getMemory().getBlock(".text");
		if (text_block != null) {
			is_go = isBuildinfoAtAddress(text_block.getStart());
		}

		// For Windows
		MemoryBlock block = program.getMemory().getBlock(".data");
		if (!is_go && block != null) {
			is_go = isBuildinfoAtAddress(block.getStart());
		}

		return is_go;
	}

	public boolean isBuildinfoAtAddress(Address address) {
		MemoryBlock block = program.getMemory().getBlock(address);
		boolean is_buildinfo = false;
		if (block != null) {
			// Golang buildinfo magic
			// https://github.com/golang/go/blob/master/src/debug/buildinfo/buildinfo.go#L170
			// ff 20 47 6f 20 62 75 69 6c 64 69 6e 66 3a
			byte[] buildinfo_magic = {-1 /*0xFF*/, 0x20, 0x47, 0x6f, 0x20, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x69, 0x6e, 0x66, 0x3a };

			Address start = address;
			is_buildinfo = true;
			for (int i = 0; i < buildinfo_magic.length; i++) {
				try {
					byte current_byte = block.getByte(start.add(i));
					if (current_byte != buildinfo_magic[i]) {
						is_buildinfo = false;
						break;
					}
				} catch (MemoryAccessException e) {
					is_buildinfo = false;
				}
			}
		}
		return is_buildinfo;
	}

	StructureDataType createGolangStructure(String type_name) throws Exception {
		StructureDataType golang_struct = new StructureDataType(
				golang_category_path,
				type_name,
				0 // 0 so Ghidra calculates from fields
		);
		golang_struct.setToDefaultPacking();
		return golang_struct;
	}

	DataType saveDataType(DataType new_data_type) throws Exception {
		return program.getDataTypeManager().addDataType(new_data_type, DataTypeConflictHandler.REPLACE_HANDLER);
	}

	DataType getGolangBuildInfoDataType() throws Exception {
		// https://github.com/golang/go/blob/master/src/debug/buildinfo/buildinfo.go#L170
		String type_name = "GolangBuildInfo";
		StructureDataType build_info = createGolangStructure(type_name);

		DataType byte_type = new ByteDataType(data_type_manager);
		DataType bool_type = new BooleanDataType(data_type_manager);
		ArrayDataType magic = new ArrayDataType(new CharDataType(data_type_manager), 13, 1, data_type_manager);
		PointerDataType gostring_pointer = new PointerDataType(getGolangStringType(), data_type_manager);

		build_info.add(byte_type, "magic", "0xFF in all known version of Go. The \\xff is invalid UTF-8, meant to make it less likely.");
		build_info.add(magic, "magic_string", "The magic string");
		build_info.add(byte_type, "pointer_size", "The pointer size in bytes");
		build_info.add(bool_type, "is_big_endian", "True for big endian, false for little endian");
		build_info.add(gostring_pointer, "build_version", "Pointer to runtime.buildVersion");
		build_info.add(gostring_pointer, "module_info", "Pointer to runtime.modinfo");
		// TODO: Next are some string data portions with the human readable version, compiler invocation, etc
		// These are called "varstrings" and use used within the loader/compiler for packed strings
		// https://github.com/golang/go/blob/db36eca33c389871b132ffb1a84fd534a349e8d8/src/encoding/binary/varint.go#L69

		return saveDataType(build_info);
	}

	DataType getSliceDataType() throws Exception {
		String type_name = "GolangSlice";
		DataType pointer = new PointerDataType(new VoidDataType(), data_type_manager);
		LongLongDataType integer = new LongLongDataType(data_type_manager);

		StructureDataType slice = createGolangStructure(type_name);
		slice.add(pointer, "array", "Pointer to the first element of the slice content");
		slice.add(integer, "len", "The current number of elements in the array");
		slice.add(integer, "cap", "The initial capacity of the Golang slice");
		return saveDataType(slice);
	}

	Data createGolangSlice(Address slice_address, DataType slice_type) throws Exception {
		Data existing_data = program.getListing().getDataContaining(slice_address);
		if (existing_data == null) {
			program.getListing().createData(slice_address, getSliceDataType());
		}

		PointerDataType content = new PointerDataType(slice_type, data_type_manager);
		LongLongDataType size = new LongLongDataType(data_type_manager);

		MemoryBufferImpl content_address_buffer = new MemoryBufferImpl(program.getMemory(), slice_address, content.getLength());
		Address content_address = PointerDataType.getAddressValue(content_address_buffer, content.getLength(), content.getDefaultSettings());

		MemoryBufferImpl size_buffer = new MemoryBufferImpl(program.getMemory(), slice_address.add(content.getLength()), size.getLength());
		long content_array_size = ((Scalar)size.getValue(size_buffer, size.getDefaultSettings(), size.getLength())).getValue();

		// This will truncate arrays larger than a 32bit int can hold.
		// TODO: We can reference this in an overlay to not destroy existing data (like the string table)
		ArrayDataType content_array = new ArrayDataType(slice_type, (int)content_array_size, slice_type.getLength(), data_type_manager);
		program.getListing().clearCodeUnits(content_address, content_address.add(content_array.getLength()), true);
		Data new_data = program.getListing().createData(content_address, content_array);
		return new_data;
	}

	DataType getBitvectorDataType() throws Exception {
		String type_name = "GolangBitVector";

		IntegerDataType uint32_t = new IntegerDataType(data_type_manager);

		// The two implementations disagree on the types used, but golang slices start
		// with a pointer so they still work interchangebly with the reflect implementation.
		// The sizes of these structures will differ though...
		// ./src/reflect/type.go	
		DataType byte_pointer = getSliceDataType(); // slices start with a pointer to the data
		// ./src/runtime/stack.go
		// PointerDataType byte_pointer = new PointerDataType(new ByteDataType(), program.getDataTypeManager());

		StructureDataType golang_bitvector_struct = createGolangStructure(type_name);
		golang_bitvector_struct.add(uint32_t, "n", "Number of bits in the bitvector");
		golang_bitvector_struct.add(byte_pointer, "bytedata", "The data in the bitvector");

		return saveDataType(golang_bitvector_struct);
	}

	/**
	* Get the {@link EnumDataType} representing the magic values used in the Golang pclntab.
	* @return {@link EnumDataType}
	* @throws Exception if a problem happens while creating the {@link DataType}
	*/
	DataType getPclntabMagicEnumDataType() throws Exception {
		String type_name = "GolangPclntabMagic";
		EnumDataType golang_pclntab_magic_enum = new EnumDataType(this.golang_category_path, type_name, 4);

		// ./src/debug/gosym/pclntab.go
		golang_pclntab_magic_enum.add("go12magic", 0xFFFFFFFb, "");
		golang_pclntab_magic_enum.add("go116magic", 0xFFFFFFFa, "");
		golang_pclntab_magic_enum.add("go118magic", 0xFFFFFFF0, "Set in commit: https://github.com/golang/go/commit/d3ad216f8e7ea7699fe44990c65213c26aba907d");
		golang_pclntab_magic_enum.add("PCLNTAB_v1", 0xFFFFFFF1, "Set in commit: https://github.com/golang/go/commit/0f8dffd0aa71ed996d32e77701ac5ec0bc7cde01");

		return saveDataType(golang_pclntab_magic_enum);
	}

	DataType getPcheaderStructureDataType() throws Exception {
		String type_name = "GolangPCHeader";
		ByteDataType byte_datatype = new ByteDataType(data_type_manager);
		IntegerDataType int_datatype = new IntegerDataType(data_type_manager);
		UnsignedIntegerDataType uint_datatype = new UnsignedIntegerDataType(data_type_manager);

		DataType generic_pointer = new PointerDataType(new VoidDataType(data_type_manager), data_type_manager);

		StructureDataType golang_pcheader_struct = this.createGolangStructure(type_name);
	  // Now let us fill in the structure
		// This structure is part of the go compiler output. The magic changes with Golang compiler versions.
		// This method implements the following:
		// https://github.com/golang/go/blob/5639fcae7fee2cf04c1b87e9a81155ee3bb6ed71/src/runtime/symtab.go#L395
		// https://github.com/golang/go/blob/f2656f20ea420ada5f15ef06ddf18d2797e18841/src/runtime/symtab.go#L407
		DataType magic_data_type = getPclntabMagicEnumDataType();
		golang_pcheader_struct.add(magic_data_type, "magic", "The pclntab magic, as defined in src/runtime/symtab.go");
		golang_pcheader_struct.add(byte_datatype, "pad0", "First padding byte");
		golang_pcheader_struct.add(byte_datatype, "pad1", "Second padding byte");
		golang_pcheader_struct.add(byte_datatype, "minLC", "min instruction size");
		golang_pcheader_struct.add(byte_datatype, "ptrSize", "size of a ptr in bytes");
		// TODO: Validate if our analysis is correct, compare the ptrSize to what Ghidra thinks the pointer size is
		golang_pcheader_struct.add(int_datatype, "nfunc", "number of functions in the module");
		golang_pcheader_struct.add(uint_datatype, "nfiles", "number of entries in the file tab");
		golang_pcheader_struct.add(uint_datatype, "textStart", "base for function entry PC offsets in this module, equal to moduledata.text");
		golang_pcheader_struct.add(uint_datatype, "funcnameOffset", "offset to the funcnametab variable from pcHeader");
		golang_pcheader_struct.add(uint_datatype, "cuOffset", "offset to the cutab variable from pcHeader");
		golang_pcheader_struct.add(uint_datatype, "filetabOffset", "offset to the filetab variable from pcHeader");
		golang_pcheader_struct.add(uint_datatype, "pctabOffset", "offset to the pctab variable from pcHeader");
		golang_pcheader_struct.add(uint_datatype, "pclnOffset", "offset to the pclntab variable from pcHeader");

		return saveDataType(golang_pcheader_struct);
	}

	DataType getFindFuncBucketDataType() throws Exception {
		String type_name = "GolangFindFuncBucket";
		UnsignedIntegerDataType uint32_t = new UnsignedIntegerDataType(program.getDataTypeManager());
		ByteDataType byte_datatype = new ByteDataType(program.getDataTypeManager());
		ArrayDataType sixteen_byte_array = new ArrayDataType(byte_datatype, 16, byte_datatype.getLength(), program.getDataTypeManager());
		// TODO: 16 byte array?
		// https://github.com/golang/go/blob/f2656f20ea420ada5f15ef06ddf18d2797e18841/src/runtime/symtab.go#L599

		StructureDataType golang_findfuncbucket_struct = createGolangStructure(type_name);
		golang_findfuncbucket_struct.add(uint32_t, "idx", "The index of this bucket in the findfunctab");
		golang_findfuncbucket_struct.add(sixteen_byte_array, "subbuckets", "The subbuckets for this bucket, used to calculate the functab index.");
		golang_findfuncbucket_struct.setToDefaultPacking();

		return saveDataType(golang_findfuncbucket_struct);
	}


	DataType getFunctabStructDataType() throws Exception {
		String type_name = "GolangFunctab";
		UnsignedIntegerDataType uint32_t = new UnsignedIntegerDataType(program.getDataTypeManager());

		StructureDataType golang_functab_struct = createGolangStructure(type_name);

		// TODO: Confirm these offsets
		golang_functab_struct.add(uint32_t, uint32_t.getLength(), "entryoff", "The offset to the entry relative to runtime.text");
		golang_functab_struct.add(uint32_t, uint32_t.getLength(), "funcoff", "The offset to the function relative to runtime.text");
		golang_functab_struct.setToDefaultPacking();

		return saveDataType(golang_functab_struct);
	}

	DataType getGolangModuleStructureDataType() throws Exception {
		String type_name = "GolangModule";
		// https://github.com/golang/go/blob/5639fcae7fee2cf04c1b87e9a81155ee3bb6ed71/src/runtime/symtab.go#L415
		DataType uint32_t = new IntegerDataType(program.getDataTypeManager());

		DataType golang_pcheader_pointer = new PointerDataType(getPcheaderStructureDataType(), program.getDataTypeManager());
		DataType golang_slice = getSliceDataType();

		DataType void_pointer = new PointerDataType(new VoidDataType(), program.getDataTypeManager());

		DataType funcbucket_pointer = new PointerDataType(getFindFuncBucketDataType(), program.getDataTypeManager());

		DataType golang_string = getGolangStringType();
		DataType bitvector = getBitvectorDataType();

		StructureDataType golang_moduleinfo_struct = createGolangStructure(type_name);
		// This structure is defined in both of these locations
		// These _should_ be in sync
		// ./src/runtime/symtab.go
		// ./src/cmd/link/internal/ld/symtab.go

		golang_moduleinfo_struct.add(golang_pcheader_pointer, "pcHeader", "Pointer to the pcHeader structure");

		golang_moduleinfo_struct.add(golang_slice, "funcnametab", "Slice of function names");
		golang_moduleinfo_struct.add(golang_slice, "cutab", "Slice of cutab?");
		golang_moduleinfo_struct.add(golang_slice, "filetab", "The filetable");
		golang_moduleinfo_struct.add(golang_slice, "pctab", "The program counter table");
		golang_moduleinfo_struct.add(golang_slice, "pclntab", "The program counter linkage table");
		golang_moduleinfo_struct.add(golang_slice, "ftab", "Function table slice");

		// This is an array of findfuncbuckets
		// We can calculate the number of buckets from the total size of the text segment and the bucket size value
		// below.
		// TODO: Get the text segment, get it's size and calculate the number of bucket required. Then create the appropriate sized
		// array
		int minfunc = 16; // https://github.com/golang/go/blob/f2656f20ea420ada5f15ef06ddf18d2797e18841/src/runtime/symtab.go#L588
		int pcbucketsize = 256 * minfunc; // https://github.com/golang/go/blob/f2656f20ea420ada5f15ef06ddf18d2797e18841/src/runtime/symtab.go#L589

		golang_moduleinfo_struct.add(funcbucket_pointer, funcbucket_pointer.getLength(), "findfunctab", "Pointer to an array of findfuncbucket structures");

		// First function
		golang_moduleinfo_struct.add(void_pointer, "minpc", "The start of the first Go function");
		golang_moduleinfo_struct.add(void_pointer, "maxpc", "The start of the last Go function, note other non-Go functions may be after this point");

		golang_moduleinfo_struct.add(void_pointer, "text", "The start of the text section");
		golang_moduleinfo_struct.add(void_pointer, "etext", "The end of the text section");

		golang_moduleinfo_struct.add(void_pointer, "noptrdata", "");
		golang_moduleinfo_struct.add(void_pointer, "enoptrdata", "");

		golang_moduleinfo_struct.add(void_pointer, "data", "The start of the data section");
		golang_moduleinfo_struct.add(void_pointer, "edata", "The end of the data section");

		golang_moduleinfo_struct.add(void_pointer, "bss", "The start of the bss section");
		golang_moduleinfo_struct.add(void_pointer, "ebss", "The end of the bss section");

		golang_moduleinfo_struct.add(void_pointer, "noptrbss", "The start of the noptrbss section");
		golang_moduleinfo_struct.add(void_pointer, "enoptrbss", "The end of the noptrbss section");

		// TODO: This is only in the newer golang compiler
		//golang_moduleinfo_struct.add(void_pointer, "covctrs", "The start of the code coverage counters section");
		//golang_moduleinfo_struct.add(void_pointer, "ecovctrs", "The end of the code coverage counters section");

		golang_moduleinfo_struct.add(void_pointer, "end", "The end?");
		golang_moduleinfo_struct.add(void_pointer, "gcdata", "Garbage collected data in the data section");
		golang_moduleinfo_struct.add(void_pointer, "gcbss", "Garbage collected data in the bss section");
		golang_moduleinfo_struct.add(void_pointer, "types", "The start of the types section");
		golang_moduleinfo_struct.add(void_pointer, "etypes", "The end of the types section");

		// TODO: This is only in the newer golang compiler
		// golang_moduleinfo_struct.add(void_pointer, "rodata", "The start of the read only data section");

		// TODO: This is only in the newer golang compiler
		// golang_moduleinfo_struct.add(void_pointer, "gofunc", "go.func.*");

		// TODO: Implement the textsect structure
		// textsectionmapSym
		golang_moduleinfo_struct.add(golang_slice, "textsectmap", "Slice of textsect structures");

		golang_moduleinfo_struct.add(golang_slice, "typelinks", "Slice of int32s, offets from types (above)");

		golang_moduleinfo_struct.add(golang_slice, "itablinks", "Slice of itab strucutres");
		golang_moduleinfo_struct.add(golang_slice, "ptab", "Slice of ptab strucutres");


		// If we're in BuildMode == BuildModePlugin
		golang_moduleinfo_struct.add(golang_string, "pluginpath", "The plugin path if compiled in BuildModePlugin");
		golang_moduleinfo_struct.add(golang_slice, "pkghashes", "A slice of modulehash structures");

		golang_moduleinfo_struct.add(golang_string, "modulename", "The name of this module, may be null");
		golang_moduleinfo_struct.add(golang_slice, "modulehashes", "A slice of modulehash structures");

		golang_moduleinfo_struct.add(new BooleanDataType(program.getDataTypeManager()), "hasmain", "True if this program has a main function");

		golang_moduleinfo_struct.add(bitvector, "gcdatamask", "The garbage collector mask for the data section");
		golang_moduleinfo_struct.add(bitvector, "gcbssmask", "The garbage collector mask for the bss section");

		golang_moduleinfo_struct.add(this.getGolangHMapDataType(), "typemap", "offset to *_rtype in previous module");

		golang_moduleinfo_struct.add(new BooleanDataType(data_type_manager), "bad", "module failed to load and should be ignored");

		golang_moduleinfo_struct.add(new PointerDataType(golang_moduleinfo_struct, data_type_manager), "next", "Next moduleinfo in the linked list");

		// TODO: Implement the rest of this structure

		return saveDataType(golang_moduleinfo_struct);
	}

	DataTypeComponent getComponentForStructField(String field, StructureDataType data_type) throws Exception {
		for (DataTypeComponent c : data_type.getComponents()) {
			if (c.getFieldName().equals(field)) {
				return c;
			}
		}
		throw new Exception("No field " + field + " in data type " + data_type.getName());
	}

	Data createGolangModuleStructure(Address address) throws Exception {
		// Clear any existing data, we will replace this with our structure
		FlatProgramAPI api = new FlatProgramAPI(program);
		DataType golang_moduleinfo_type = getGolangModuleStructureDataType();
		program.getListing().clearCodeUnits(address, address.add(golang_moduleinfo_type.getLength()), true);
		Data golang_moduleinfo = program.getListing().createData(address, golang_moduleinfo_type);

		// Get the ftab entry
		Data ftab = golang_moduleinfo.getComponent(6);
		// Get the `array` component of the ftab struct
		Data ftab_address_data = ftab.getComponent(0);
		// Get the `len` component of the ftab struct
		Data ftab_length = ftab.getComponent(1);
		// Cast the values to the appropriate types
		Address ftab_address = ((Address)ftab_address_data.getValue());
		long nfuncs = ((Scalar)ftab_length.getValue()).getValue();

		// Now we know the length, let's create our array of functab entries
		DataType functab_data_type = getFunctabStructDataType();
		ArrayDataType func_array = new ArrayDataType(functab_data_type, (int)nfuncs, functab_data_type.getLength());
		Data function_table = program.getListing().createData(ftab_address, func_array);
		Symbol text_symbol = getRuntimeTextSymbol();

		// Now we can iterate over each element of the functab array and
		// create any missing functions.
		for (int i = 0; i < nfuncs; i++) {
			Data entry = function_table.getComponent(i);
			long entry_offset = ((Scalar)entry.getComponent(0).getValue()).getValue();
			long func_offset = ((Scalar)entry.getComponent(1).getValue()).getValue();

			Address function_entry = text_symbol.getAddress().add(entry_offset);

			api.createMemoryReference(entry.getComponent(0), function_entry, RefType.DATA_IND);
			if (api.getFunctionAt(function_entry) == null) {
				// null name indicates a default name is to be set
				api.createFunction(function_entry, null);
			}
		}

		return golang_moduleinfo;
	}

	DataType getGolangHashmapBucketDataType() throws Exception {
		throw new NotYetImplementedException();
	}

	DataType getGolangHMapDataType() throws Exception {
		String type_name = "GolangHMap";

		DataType int_type = new IntegerDataType(data_type_manager);
		DataType ubyte = new ByteDataType(data_type_manager);
		DataType short_type = new ShortDataType(data_type_manager);
		DataType uint32_t = new UnsignedIntegerDataType(data_type_manager);
		DataType void_pointer = new PointerDataType(new VoidDataType(), data_type_manager);

		// TODO: ./src/runtime/map.go
		// _and_ in cmd/compile/internal/reflectdata/reflect.go
		StructureDataType hashmap = createGolangStructure(type_name);

		hashmap.add(int_type, "count", "# live cells == size of map.  Must be first (used by len() builtin)");
		hashmap.add(ubyte, "flags", "Map flags?");
		hashmap.add(ubyte, "B", "log_2 of # of buckets (can hold up to loadFactor * 2^B items)");
		hashmap.add(short_type, "noverflow", "approximate number of overflow buckets; see incrnoverflow for details");
		hashmap.add(uint32_t, "hash0", "hash seed");
		hashmap.add(void_pointer, "buckets", "array of 2^B Buckets. may be nil if count==0");
		hashmap.add(void_pointer, "oldbuckets", "previous bucket array of half the size, non-nil only when growing");
		hashmap.add(new LongLongDataType(data_type_manager), "nevactuate", "progress counter for evacuation (buckets less than this have been evacuated)");
		// TODO This is a mapextra strucutre from ./src/runtime/map.go
		hashmap.add(void_pointer, "extra", "optional fields (mapextra structure)");

		// According to the comment in ./src/runtime/map.go:
		// The size of hmap should be 48 bytes on 64 bit
	  // and 28 bytes on 32 bit platforms.
		return saveDataType(hashmap);
	}

	Data createPcheader(Address address) throws Exception {
		DataType pcheader = getPcheaderStructureDataType();
		FlatProgramAPI api = new FlatProgramAPI(program);
		api.clearListing(address, address.add(pcheader.getLength()));

		// TODO: Extract the values from the structure and add xrefs to discover things and allow
		// other analysis modules to use these to find things like functions and strings.
		return api.createData(address, pcheader);
	}

	DataType getGolangStringType() throws Exception {
		String type_name = "GolangString";
		
		DataType char_pointer = new PointerDataType(new CharDataType(data_type_manager), data_type_manager);
		DataType length = new LongLongDataType(data_type_manager);
		
		// Get the size field the same way Go's debugger does
		// https://github.com/golang/debug/blob/36716089901d6bd6afeaa2677562ce1491eb20c1/internal/core/read.go#L124
		
		StructureDataType golang_string_structure = createGolangStructure(type_name);
		golang_string_structure.add(char_pointer, "content", "Pointer to the string content");
		golang_string_structure.add(length, "length", "The length of the string content in bytes");
		
		return saveDataType(golang_string_structure);
	}

	Symbol getPclntabSymbol() {
		Symbol found = program.getSymbolTable().getSymbols("_runtime.pclntab").next();
		if (found == null) {
			found = program.getSymbolTable().getSymbols("runtime.pclntab").next();
		}

		return found;
	}

	Symbol getFirstModuleDataSymbol() {
		Symbol found = program.getSymbolTable().getSymbols("_runtime.firstmoduledata").next();
		if (found == null) {
			found = program.getSymbolTable().getSymbols("runtime.firstmoduledata").next();
		}
		return found;
	}

	Symbol getModuleSliceSymbol() {
		Symbol found = program.getSymbolTable().getSymbols("_runtime.modulesSlice").next();
		if (found == null) {
			found = program.getSymbolTable().getSymbols("runtime.modulesSlice").next();
		}
		return found;
	}

	Symbol getRuntimeTextSymbol() {
		Symbol found = program.getSymbolTable().getSymbols("_runtime.text").next();
		if (found == null) {
			MemoryBlock text_block = program.getMemory().getBlock(".text");
			try {
				program.getSymbolTable().createLabel(text_block.getStart(), "runtime.text", SourceType.ANALYSIS);
			} catch (Exception e) {
				// we tried
			}
			found = program.getSymbolTable().getSymbols("runtime.text").next();

		}
		return found;
	}

}
