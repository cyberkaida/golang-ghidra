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
import ghidra.program.model.data.BooleanDataType;
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
		GolangTypes golang_types = new GolangTypes(program);
		return golang_types.isGo();
	}

	private DataType findFirstDataType(Program program, String name) throws Exception {
		ArrayList<DataType> type_list = new ArrayList<>();
		program.getDataTypeManager().findDataTypes(name, type_list);
		if (type_list.size() == 0) {
			throw new Exception("DataType " + name + " could not be found. Is the data type defined in your program's DataTypes?");
		}
		
		return type_list.get(0);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
			try {


				GolangTypes golang_types = new GolangTypes(program);
				FlatProgramAPI api = new FlatProgramAPI(program, monitor);
				// Parse the pcheader structure
				monitor.setMessage("Parsing Golang pcheader");


				Address go_build_info = program.getMemory().getBlock("__go_buildinfo").getStart();
				api.createData(go_build_info, golang_types.getGolangBuildInfoDataType());
				Symbol runtime_pclntab = program.getSymbolTable().getSymbols("_runtime.pclntab").next();
				Address pcheader_address = runtime_pclntab.getAddress();

				Data pcheader = golang_types.createPcheader(pcheader_address);

				// Parse the module info table
				Symbol first_module_info = program.getSymbolTable().getSymbols("_runtime.firstmoduledata").next();
				Address first_module_address = first_module_info.getAddress();
				golang_types.createGolangModuleStructure(first_module_address);

				Symbol module_slice = program.getSymbolTable().getSymbols("_runtime.modulesSlice").next();
				api.createData(module_slice.getAddress(), new PointerDataType(golang_types.getGolangModuleStructureDataType(), program.getDataTypeManager()));

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
