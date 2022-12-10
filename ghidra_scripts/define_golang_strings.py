#!/usr/bin/env python2
# @author CyberKaida
# @category kaida
# @menupath Analysis.Experimental.Go Strings
import ghidra
from ghidra.program.model.symbol import RefType
from ghidra.program.model.symbol import SourceType

program = currentProgram

function_manager = program.getFunctionManager()
function_iterator = function_manager.getFunctions(True)
maximum_string_length = 4096

golang_string_data_type = getDataTypes("GolangString")[0]
print(golang_string_data_type)

for f in function_iterator:
    for addr in f.getBody().getAddresses(True):
        references = getReferencesFrom(addr)
        for ref in references:
            is_data = ref.getReferenceType() is RefType.DATA
            is_memory = ref.isMemoryReference()
            if is_data and is_memory:
                to_address = ref.getToAddress()
                to_address_data = getDataAt(to_address)
                if not to_address_data: continue
                is_pointer = to_address_data.isPointer()
                if is_pointer:
                    next_address = to_address_data.getMaxAddress().next()
                    string_address = to_address_data.getValue()

                    possible_length_value = getLong(next_address)
                    if possible_length_value > maximum_string_length: continue
                    struct_size = golang_string_data_type.getLength()
                    end_struct_address = to_address.add(struct_size)
                    # Create a checkpoint


                    clearListing(to_address, end_struct_address)
                    createData(to_address, golang_string_data_type)

                    length_value = possible_length_value
                    # TODO: get the value out of the struct instead
                    
                    # Now we have the data type set for the structure
                    # We will go to the `to_address` and retrieve the string
                    # to construct a label
                    clearListing(string_address, string_address.add(length_value))
                    createAsciiString(string_address, length_value)

                    string_data = getDataAt(string_address)
                    string_symbol = getSymbolAt(string_address)

                    createLabel(to_address, "g_" + string_symbol.getName(), True, SourceType.ANALYSIS)
                    
                    print(string_data.getValue())
