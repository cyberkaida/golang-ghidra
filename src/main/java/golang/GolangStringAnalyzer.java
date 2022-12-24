/**
 * 
 */
package golang;

import java.util.ArrayList;

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
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.StringDataType;
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
public class GolangStringAnalyzer implements Analyzer {

	private int maximum_string_length = 4096;
	static String maximum_string_length_option_name = "Maximum String Length";
	
	
	@Override
	public String getName() {
		return "Golang Strings";
	}

	@Override
	public AnalyzerType getAnalysisType() {
		return AnalyzerType.FUNCTION_ANALYZER;
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return true;
	}

	@Override
	public boolean supportsOneTimeAnalysis() {
		return false;
	}

	@Override
	public String getDescription() {
		return "Extract Golang strings";
	}

	@Override
	public AnalysisPriority getPriority() {
		// We need to run after function identification and string definition
		return AnalysisPriority.LOW_PRIORITY;
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getCompilerSpec().getCompilerSpecID().getIdAsString().equals("golang");
	}

	private DataType getGolangStringType(Program program) throws Exception {
		CategoryPath golang_category_path = new CategoryPath(CategoryPath.ROOT, "Golang");
		DataType golang_string = program.getDataTypeManager().getDataType("/Golang/GolangString");
		
		if (golang_string == null) {
			DataType char_type = program.getDataTypeManager().getDataType("/char");
			DataType char_pointer = program.getDataTypeManager().getPointer(char_type);
			DataType pointer = char_pointer;
			
			if (pointer == null) {
				throw new Exception("Could not find char* DataType");
			}
			
			DataType length = null;
			// Get the size field the same way Go's debugger does
			// https://github.com/golang/debug/blob/36716089901d6bd6afeaa2677562ce1491eb20c1/internal/core/read.go#L124
			
			if (pointer.getLength() == 8) {
				// 64 bit
				length = program.getDataTypeManager().getDataType("/ulonglong");
			} else if (pointer.getLength() == 4) {
				// 32 bit
				length = program.getDataTypeManager().getDataType("/uint");
			} else {
				// ???? bit
				ArrayList<DataType> type_list = new ArrayList<>();
				program.getDataTypeManager().findDataTypes("size_t", type_list);
				if (type_list.size() == 0) {
					throw new Exception("size_t DataType could not be found. Is size_t defined in your program's DataTypes?");
				}
				
				length = type_list.get(0);
			}
			
			if (length == null) {
				throw new Exception("size_t DataType not defined. Is size_t defined in your program's DataTypes?");
			}
			
			Category golang_category = program.getDataTypeManager().createCategory(golang_category_path);
			
			StructureDataType golang_string_structure = new StructureDataType(
					golang_category_path,
					"GolangString",
					0
			);
			
			golang_string_structure.add(pointer, pointer.getLength(), "content", "Pointer to the string content");
			golang_string_structure.add(length, length.getLength(), "length", "The length of the string content in bytes");
			
			
			golang_string = program.getDataTypeManager().addDataType(golang_string_structure, DataTypeConflictHandler.KEEP_HANDLER);
		}
		return golang_string;
	}
	
	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		
		// Get the datatype
		DataType golang_string;
		try {
			golang_string = this.getGolangStringType(program);
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
		
		FunctionManager function_manager = program.getFunctionManager();
		FunctionIterator function_iterator = function_manager.getFunctions(true);
		
		while (function_iterator.hasNext()) {
			Function f = function_iterator.next();
			AddressIterator function_body = f.getBody().getAddresses(true);
			while (function_body.hasNext()) {
				Address addr = function_body.next();
				Reference[] references = program.getReferenceManager().getReferencesFrom(addr);
				for (Reference reference : references) {
					boolean is_data = reference.getReferenceType() == RefType.DATA;
					boolean is_memory = reference.isMemoryReference();
					
					if (is_data && is_memory) {
						Address to_address = reference.getToAddress();
						Data to_address_data = program.getListing().getDataAt(to_address);
						if (to_address_data == null) {
							continue;
						}
						boolean is_pointer = to_address_data.isPointer();
						
						if (is_pointer) {
							Address string_address = (Address) to_address_data.getValue();
							Address next_address = to_address_data.getMaxAddress().next();
							try {
								long possible_length_value = program.getMemory().getLong(next_address);
								if (possible_length_value > this.maximum_string_length) {
									continue;
								}
								
								// At this point we think we have a valid structure
								long struct_size = golang_string.getLength();
								Address end_struct_address = to_address.add(struct_size);
								
								// Here we start to edit the analysis
								
								// TODO: Get the project from the program and create a checkpoint
								
								// Get the existing data out of the way
								program.getListing().clearCodeUnits(to_address, end_struct_address, true);
								program.getListing().createData(to_address, golang_string);
								
								// We need to drop to an integer here because Ghidra only accepts int as a length below
								int length_value = (int) possible_length_value;
								program.getListing().clearCodeUnits(string_address, string_address.add(length_value), true);
								program.getListing().createData(string_address, StringDataType.dataType, length_value);
								
								String string_data = (String)program.getListing().getDataAt(string_address).getValue();
								Symbol string_symbol = program.getSymbolTable().getPrimarySymbol(string_address);
								program.getSymbolTable().createLabel(to_address, "g_" + string_symbol.getName(), SourceType.ANALYSIS);
							} catch (MemoryAccessException e) {
								// This is thrown if there are not enough bytes to create a long
								e.printStackTrace();
								continue;
							} catch (CodeUnitInsertionException e) {
								// This can happen when we didn't clear the code units correctly
								e.printStackTrace();

								continue;
							} catch (InvalidInputException e) {
								// This can happen when we create out label
								e.printStackTrace();
								continue;
							}
							
							
						}
					}
					

				}
			}
			
		}
		
		return false;
	}

	@Override
	public boolean removed(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		return false;
	}

	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(GolangStringAnalyzer.maximum_string_length_option_name, OptionType.INT_TYPE, 4096, new HelpLocation("Golang", null), "The maximum size for a Golang string. Anything larger than this value will be ignored");

	}

	@Override
	public void optionsChanged(Options options, Program program) {
		this.maximum_string_length = options.getInt(GolangStringAnalyzer.maximum_string_length_option_name, 4096);
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
