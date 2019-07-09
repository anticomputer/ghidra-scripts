//Group string references by function
//@author Bas Alberts
//@category Analysis 
//@keybinding alt-0
//@menupath 
//@toolbar 

// Note: to enable this in your codebrowser via the Alt-0 shortcut (SARK style) make sure the script is selected in your script manager
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
    private File logFile;
    private PrintWriter logWriter;
    private IsolatedEntrySubModel subModel;
    private TableChooserDialog tableDialog;
        
    private void logLine(String line) {
        if (logWriter != null) {
            logWriter.println(line);
        }
        println(line);
        return;
    }
    
    private void checkFunc(Function f) throws Exception {
        boolean functionRefsStrings = false;
        CodeBlockIterator subIter = subModel.getCodeBlocksContaining(f.getBody(), monitor);
        while (subIter.hasNext()) {
            // get a single code block
            CodeBlock block = subIter.next();
            // walk the addresses for the code block
            AddressIterator blockAddresses = block.getAddresses(true);
            while (blockAddresses.hasNext()) {
                Address blockAddress = blockAddresses.next();
                // check if the instruction has a reference to any known string
                Instruction instruction = listing.getInstructionAt(blockAddress);
                if (instruction == null) {
                    continue;
                }
                Reference[] references = instruction.getReferencesFrom();
                for (Reference ref : references) {
                    if (stringMap.containsKey(ref.getToAddress())) {
                        if (functionRefsStrings == false) {
                            logLine("### " + f.getName());
                            functionRefsStrings = true;
                        }
                        Data stringData = stringMap.get(ref.getToAddress());
                        String stringValue = stringData.getDefaultValueRepresentation();
                        logLine(blockAddress + ": " + stringValue);
                        tableDialog.add(new FuncStringRef(f, blockAddress, stringValue, stringData.getAddress()));
                    }
                }
            }
        }
        if (functionRefsStrings == true) {
            logLine("");
        }
    }
    
    private boolean openLog() throws Exception {
        logFile = askFile("Choose File Location", "Save");
        if (logFile.exists()) {
            if (!askYesNo("File Exists", "Overwrite Existing File?")) {
                println("Aborting!");
                logWriter = null;
                return false;
            }
        }
        try {
            logWriter = new PrintWriter(new FileOutputStream(logFile));
        }
        catch (FileNotFoundException e) {
            println("File not found!");
            logWriter = null;
            return false;
        }
        return true;
    }
    
    public void getStringAddresses() throws Exception {
        // step 1: get all known string addresses
        DataIterator dataIter = listing.getDefinedData(true);
        while (dataIter.hasNext() && !monitor.isCancelled()) {
            Data data = dataIter.next();
            String type = data.getDataType().getName().toLowerCase();
            if ((type.contains("unicode") || type.contains("string"))) {
                stringMap.put(data.getAddress(), data);
            }
        }        
    }  
    
    public void run() throws Exception {
        
        if (currentProgram == null) {
            println("No current program!");
            return;
        }
        
        listing = currentProgram.getListing();
        stringMap = new HashMap<>();
                        
        // create a table to toss results into
        tableDialog = createTableChooserDialog(currentProgram.getName() + ": grouped string references", null);
        configureTableColumns(tableDialog);
        
        subModel = new IsolatedEntrySubModel(currentProgram);
        // handle just current function if an address is selected
        if (currentAddress != null) {
            Function f = listing.getFunctionContaining(currentAddress);
            if (f == null) {
                println("No function found at current address!");
                return;
            }
            getStringAddresses();
            checkFunc(f);
        }
        // handle all functions
        else {
            openLog();
            getStringAddresses();
            FunctionIterator functionIter = listing.getFunctions(true);
            while (functionIter.hasNext() && !monitor.isCancelled()) {
                checkFunc(functionIter.next());
            }
        }
        		
        if (logWriter != null) {
            logWriter.close();
            println("Results written to: " + logFile.getAbsolutePath());
        }
        
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
