//Group string references by function
//@author Bas Alberts
//@category Analysis 
//@keybinding 
//@menupath 
//@toolbar 

// Disclaimer: this was mostly copy pasted together from existing Ghidra scripts and I claim no copyright to this horrid pile of Java :)

import ghidra.app.script.GhidraScript;
import ghidra.app.tablechooser.AbstractComparableColumnDisplay;
import ghidra.app.tablechooser.AddressableRowObject;
import ghidra.app.tablechooser.ColumnDisplay;
import ghidra.app.tablechooser.StringColumnDisplay;
import ghidra.app.tablechooser.TableChooserDialog;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.PrintWriter;
import java.util.HashMap;

public class StringGroup extends GhidraScript {
        
    private Listing listing;
    private HashMap<Address, Data> stringMap;
    private HashMap<Address, Data> instructionMap;
    private File logFile;
    private PrintWriter logWriter;
        
    private void logLine(String line) {
        if (logWriter != null) {
            logWriter.println(line);
        }
        println(line);
        return;
    }

    public void run() throws Exception {
        listing = currentProgram.getListing();
        stringMap = new HashMap<>();
        instructionMap = new HashMap<>();
        
        // get a log file to log results to
        logFile = askFile("Choose File Location", "Save");
        if (logFile.exists()) {
            if (!askYesNo("File Exists", "Overwrite Existing File?")) {
                println("Aborting!");
                return;
            }
        }
        try {
            logWriter = new PrintWriter(new FileOutputStream(logFile));
        }
        catch (FileNotFoundException e) {
            println("File not found!");
            return;
        }
                
        // create a table to toss results into
        TableChooserDialog tableDialog = createTableChooserDialog(currentProgram.getName() + ": grouped string references", null);
        configureTableColumns(tableDialog);
        
        // step 1: get all known string addresses
        DataIterator dataIter = listing.getDefinedData(true);
        while (dataIter.hasNext() && !monitor.isCancelled()) {
            // we could do a data.getReferenceIteratorTo() type logic but that becomes less convenient to expand on
            Data data = dataIter.next();
            String type = data.getDataType().getName().toLowerCase();
            if ((type.contains("unicode") || type.contains("string"))) {
                stringMap.put(data.getAddress(), data);
            }
        }
        
        // step 2 get addresses of all instructions containing reference to any of those string addresses
        InstructionIterator instructionsIter = listing.getInstructions(currentProgram.getMemory(), true);
        while (instructionsIter.hasNext() && !monitor.isCancelled()) {
            Instruction instruction = instructionsIter.next();
            Reference[] references = instruction.getReferencesFrom();
            for (Reference ref : references) {
                if (stringMap.containsKey(ref.getToAddress())) {
                    instructionMap.put(instruction.getAddress(), stringMap.get(ref.getToAddress()));
                }
            }
        }

        // step 3: check if those addresses are in the body address range of any function
        FunctionIterator iter = listing.getFunctions(true);
        IsolatedEntrySubModel submodel = new IsolatedEntrySubModel(currentProgram);
        // check all the codeblocks of a function for string references
        while (iter.hasNext() && !monitor.isCancelled()) {
            Function f = iter.next();
            boolean functionRefsStrings = false;
            CodeBlockIterator subIter = submodel.getCodeBlocksContaining(f.getBody(), monitor);
            while (subIter.hasNext()) {
                // get a single code block
                CodeBlock block = subIter.next();
                // walk the instructions for the code block ... low to high
                AddressIterator blockAddresses = block.getAddresses(true);
                while (blockAddresses.hasNext()) {
                    Address blockAddress = blockAddresses.next();
                    if (instructionMap.containsKey(blockAddress)) {
                        if (functionRefsStrings == false) {
                            logLine("### " + f.getName());
                            functionRefsStrings = true;
                        }
                        Data stringData = instructionMap.get(blockAddress);
                        String stringValue = stringData.getDefaultValueRepresentation();
                        // log results
                        logLine(blockAddress + ": " + stringValue);
                        // table results
                        tableDialog.add(new FuncStringRef(f, blockAddress, stringValue, stringData.getAddress()));
                    }
                }
            }
            if (functionRefsStrings == true) {
                logLine("");
            }
        }
		
        logWriter.close();
        println("Results written to: " + logFile.getAbsolutePath());
        
        // show the result table
        tableDialog.show();
   		
        return;
    }
    
    // Note: most all of the below was gacked from CompareFunctionSizesScript.java
    
    static class FuncStringRef implements AddressableRowObject {
		
        private Address stringAddress;
        private Address stringReference;
        private String stringValue;
        private Function func;

        public FuncStringRef(Function f, Address xref, String s, Address a) {
            func = f;
            stringReference = xref;
            stringAddress = a;
            stringValue = s;
        }

        public Address getStringReference() {
            return stringReference;
        }
		
        public String getStringValue() {
            return stringValue;
        }
        
        public Address getStringAddress() {
            return stringAddress;
        }

        public Function getFunction() {
            return func;
        }

        @Override
        public String toString() {
            StringBuffer sb = new StringBuffer();
            sb.append(func.getName());
            sb.append(" " + stringReference + " reference to: ");
            sb.append(stringValue);
            return sb.toString();
        }

        @Override
        public Address getAddress() {
            return func.getEntryPoint();
        }
    }
    
    interface RowEntries {
        void add(FuncStringRef row);
        void setMessage(String message);
        void clear();
    }

    class TableEntryList implements RowEntries {
		
        private TableChooserDialog tDialog;

        public TableEntryList(TableChooserDialog dialog) {
            tDialog = dialog;
        }

        @Override
        public void add(FuncStringRef row) {
            tDialog.add(row);

        }

        @Override
        public void setMessage(String message) {
            tDialog.setMessage(message);

        }

        @Override
        public void clear() {
            return;
        }
    }

    private void configureTableColumns(TableChooserDialog dialog) {
		
        StringColumnDisplay functionNameColumn = new StringColumnDisplay() {
                @Override
                public String getColumnName() {
                    return "Function Name";
                }

                @Override
                public String getColumnValue(AddressableRowObject rowObject) {
                    return ((FuncStringRef) rowObject).getFunction().getName();
                }
            };

        ColumnDisplay<Address> stringReferenceColumn = new AbstractComparableColumnDisplay<Address>() {

                @Override
                public Address getColumnValue(AddressableRowObject rowObject) {
                    return ((FuncStringRef) rowObject).getStringReference();
                }

                @Override
                public String getColumnName() {
                    return "String XRef";
                }
            };

        ColumnDisplay<String> stringValueColumn = new AbstractComparableColumnDisplay<String>() {

                @Override
                public String getColumnValue(AddressableRowObject rowObject) {
                    return ((FuncStringRef) rowObject).getStringValue();
                }

                @Override
                public String getColumnName() {
                    return "String Value";
                }
            };
            
        ColumnDisplay<Address> stringAddressColumn = new AbstractComparableColumnDisplay<Address>() {

                @Override
                public Address getColumnValue(AddressableRowObject rowObject) {
                    return ((FuncStringRef) rowObject).getStringAddress();
                }

                @Override
                public String getColumnName() {
                    return "String Address";
                }
            };

        dialog.addCustomColumn(functionNameColumn);
        dialog.addCustomColumn(stringReferenceColumn);
        dialog.addCustomColumn(stringValueColumn);
        dialog.addCustomColumn(stringAddressColumn);
    }
}
