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
import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.PrintWriter;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

public class StringGroup extends GhidraScript {
        
    private Listing listing;
    private File logFile;
    private PrintWriter logWriter;
    private TableChooserDialog tableDialog;
    private boolean emptyTable;
    
    private HashMap<Function, ArrayList<Map.Entry<Instruction, Data>>> functionReference;
    private HashMap<Instruction, Data> nonFunctionReference;
        
    private void logLine(String line) {
        if (logWriter != null) {
            logWriter.println(line);
        }
        println(line);
        return;
    }
    
    private void checkNonFunctionReferences() throws Exception {
        for (Map.Entry<Instruction, Data> xref : nonFunctionReference.entrySet()) {
            Address xrefAddress = xref.getKey().getAddress();
            Address stringAddress = xref.getValue().getAddress();
            String stringValue = xref.getValue().getDefaultValueRepresentation();
            logLine(xrefAddress + ": " + stringValue);
            logLine("### non-function reference @" + xrefAddress + ": " + stringValue);
            tableDialog.add(new FuncStringRef(null, xrefAddress, stringValue, stringAddress));
            emptyTable = false;
        }
    }
    
    private void checkFunction(Function f) throws Exception {
        if (functionReference.containsKey(f)) {
            logLine("### " + f.getName());
            ArrayList<Map.Entry<Instruction, Data>> xrefs = functionReference.get(f);
            for (Map.Entry<Instruction, Data> xref : xrefs) {
                Address xrefAddress = xref.getKey().getAddress();
                Address stringAddress = xref.getValue().getAddress();
                String stringValue = xref.getValue().getDefaultValueRepresentation();
                logLine(xrefAddress + ": " + stringValue);
                tableDialog.add(new FuncStringRef(f, xrefAddress, stringValue, stringAddress));
                emptyTable = false;
            }
            logLine("");
        }
    }
    
    private boolean openLog() throws Exception {
        logFile = askFile("Choose File Location", "Save");
        if (logFile.exists()) {
            if (!askYesNo("File Exists", "Overwrite Existing File?")) {
                println("Aborting!");
                return false;
            }
        }
        try {
            logWriter = new PrintWriter(new FileOutputStream(logFile));
        }
        catch (FileNotFoundException e) {
            println("File not found!");
            return false;
        }
        return true;
    }
    
    public void getStringReferences() throws Exception {
        DataIterator dataIter = listing.getDefinedData(true);
        while (dataIter.hasNext() && !monitor.isCancelled()) {
            Data data = dataIter.next();
            String type = data.getDataType().getName().toLowerCase();
            // XXX: see if there is a better API for determining string data types
            if ((type.contains("unicode") || type.contains("string"))) {
                ReferenceIterator refIter = data.getReferenceIteratorTo();
                while (refIter.hasNext() && !monitor.isCancelled()) {
                    Address fromAddress = refIter.next().getFromAddress();
                    Function f = listing.getFunctionContaining(fromAddress);
                    Instruction i = listing.getInstructionAt(fromAddress);
                    // matched reference to an instruction belonging to a function
                    if (f != null && i != null) {
                        Map.Entry<Instruction, Data> xref = new AbstractMap.SimpleEntry<>(i, data);
                        if (functionReference.containsKey(f)) {
                            functionReference.get(f).add(xref);
                        } else {
                            ArrayList<Map.Entry<Instruction, Data>> xrefList = new ArrayList<>();
                            xrefList.add(xref);
                            functionReference.put(f, xrefList);
                        }
                    }
                    // matched reference to an instruction not belonging to a function
                    else if (i != null) {
                        nonFunctionReference.put(i, data);
                    } else {
                        logLine("###: no function or instruction for string reference @" + fromAddress);
                    }
                }
            }
        }        
    }  
    
    public void run() throws Exception {
        
        if (currentProgram == null) {
            println("No current program!");
            return;
        }
        
        // things we need for our analysis
        listing = currentProgram.getListing();
        functionReference = new HashMap<>();
        nonFunctionReference = new HashMap<>();
                        
        // create a table to toss results into
        tableDialog = createTableChooserDialog(currentProgram.getName() + ": grouped string references", null);
        configureTableColumns(tableDialog);
        emptyTable = true;

        // handle single function if current address is a function ... give option to handle all functions if not
        if (currentAddress != null && listing.getFunctionContaining(currentAddress) != null) {
            getStringReferences();
            checkFunction(listing.getFunctionContaining(currentAddress));
           
        }
        // do a full analysis run
        else if (askYesNo("No Current Function", "Process all Functions?")) {
            if (askYesNo("Log Results", "Log results to disk?")) {
                openLog();
            } else {
                logWriter = null;
            }
            getStringReferences();
            FunctionIterator functionIter = listing.getFunctions(true);
            while (functionIter.hasNext() && !monitor.isCancelled()) {
                checkFunction(functionIter.next());    
            }   
            checkNonFunctionReferences();
        } else 
            return;
                        
        if (logWriter != null) {
            logWriter.close();
            println("Results written to: " + logFile.getAbsolutePath());
        }
        
        // don't be annoying and only pop up a table when we have results to show
        if (emptyTable == false) {
            tableDialog.show();
        } else {
            tableDialog.close();
        }
                
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
            String fName;
            
            if (func == null) {
                fName = "NO FUNCTION DEFINED";
            } else {
                fName = func.getName();
            }
            StringBuffer sb = new StringBuffer();
            sb.append(fName);
            sb.append(" " + stringReference + " reference to: ");
            sb.append(stringValue);
            return sb.toString();
        }

        @Override
        public Address getAddress() {
            if (func == null ) {
                // return the string reference instead
                return stringReference;
            }
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
                    Function f = ((FuncStringRef) rowObject).getFunction();
                    if (f == null) {
                        return "NO FUNCTION DEFINED";
                    }
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
