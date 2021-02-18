
//
//Launches a GUI allowing users to generate VTGREP search strings based on a set of selected instructions and query VT.
// Based on GHIDRA's yara plugin
// This version is experimental, might be unstable. 
// Current known bugs: near branches gets masked out because OperandType.RELATIVE isn't correctly set by GHIDRA, as a workaround you can use the GUI panel to mask/unmask specific bytes.
//@author: Kasif Dekel (@kasifdekel)
//@category Search.VTGREP
//@keybinding ctrl alt F9
//@menupath Search.VTgrepGHIDRA
//@toolbar vtgrepbutton.jpg
import docking.widgets.EmptyBorderButton;
import generic.continues.RethrowContinuesFactory;
import ghidra.app.plugin.core.instructionsearch.InstructionSearchPlugin;
import ghidra.app.plugin.core.instructionsearch.model.InstructionSearchData.UpdateType;
import ghidra.app.plugin.core.instructionsearch.model.InstructionTableDataObject;
import ghidra.app.plugin.core.instructionsearch.model.InstructionTableModel;
import ghidra.app.plugin.core.instructionsearch.ui.AbstractInstructionTable.OperandState;
import ghidra.app.plugin.core.instructionsearch.ui.InstructionSearchDialog;
import ghidra.app.plugin.core.instructionsearch.ui.InstructionTable;
import ghidra.app.plugin.core.instructionsearch.ui.InstructionTablePanel;
import ghidra.app.plugin.core.instructionsearch.util.InstructionSearchUtils;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.bin.format.pe.*;
import ghidra.app.util.bin.format.pe.PortableExecutable.SectionLayout;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.mem.Memory;
import ghidra.util.MD5Utilities;
import ghidra.util.Msg;
import org.apache.commons.io.IOUtils;
import resources.ResourceManager;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Observable;
import java.util.HashMap;
import java.util.Map;

public class VTgrepGHIDRA extends GhidraScript {

    public static final int MIN_QUERY_LEN = 10;
    public static final int MAX_QUERY_LEN = 4096;

    private InstructionSearchPlugin plugin;

    private InstructionSearchDialog dialog;

    private String currentSTR;


    @Override
    protected void run() throws Exception {

        plugin = InstructionSearchUtils.getInstructionSearchPlugin(state.getTool());

        if (plugin == null) {
            popup("Instruction Pattern Search plugin not installed! Please install and re-run script.");
            return;
        }

        if (currentProgram == null) {
            popup("Please open a program before running this script.");
            return;
        }

        if (currentSelection == null) {
            popup("Please make a valid selection in the program and select 'reload'.");
        }

        dialog = new YaraDialog();
        state.getTool().showDialog(dialog);

        dialog.loadInstructions(plugin);
    }


    private String generateYaraString(String ruleName) {

        StringBuilder yaraString = new StringBuilder("\n\nrule " + ruleName + "\n");
        yaraString.append("{\n\tstrings:\n");

        String fullStr = "";
        String currStr = "";
        String lc = "";
        boolean isWildcards;

        if (dialog == null || dialog.getSearchData() == null) {
            return null;
        }
        String instrStr = dialog.getSearchData().getCombinedString();

        for (int i = 0; i < instrStr.length(); i += 8) {
            isWildcards = false;
            String curByte = instrStr.length() >= 8 ? instrStr.substring(i, i + 8) : instrStr.substring(i);
            String nibble1 = curByte.length() >= 4 ? curByte.substring(0, 4) : curByte;
            String nibble2 = curByte.length() >= 8 ? curByte.substring(4, 8)
                    : curByte.length() >= 4 ? curByte.substring(4) : "";

            if (nibble1.contains(".") || nibble2.contains(".")) {
                currStr = "??";
                isWildcards = true;
            } else {
                currStr = InstructionSearchUtils.toHex(nibble1, false).trim();
                currStr += InstructionSearchUtils.toHex(nibble2, false).trim();
            }

            if (fullStr.isEmpty()) {
                fullStr += currStr;
                continue;
            }
            lc = fullStr.substring(fullStr.length() - 1);
            fullStr += (lc.equals("?") ? (isWildcards ? currStr : " " + currStr) : (isWildcards ? " " + currStr : currStr));

        }

        currentSTR = fullStr;
        println(currentSTR);
        yaraString.append("\t\t$STR" + 1 + " = { " + fullStr + " }\n");
        yaraString.append("\n\tcondition:\n");
        yaraString.append("\t\t$STR1");
        yaraString.append("\n}\n");

        return yaraString.toString();
    }


    interface Slice {
        void append(Slice slice);

        String get();

        int len();

        boolean combinable(Slice next);

        Slice combine(Slice next);

        Slice mask();

        boolean canCombine();
    }


    private class YaraDialog extends InstructionSearchDialog {

        JScrollPane scrollPane;
        private JTextArea yaraTA;
        private JSplitPane verticalSplitter;

        private int splitterSave = 200;

        private YaraDialog() {
            super(plugin, "Yara Rule Generator + VTgrepGHIDRA", null);
            revalidate();
            setPreferredSize(500, 400);
        }
        
        String GetSerial(String text) throws Exception { 
        	int f = text.indexOf("Serial : ");
        	if(f == -1) { 
        		throw new Exception("Please verify that osslsigncode is installed.");
        	}
    		String middle = text.substring(f + 9);
    		return middle.substring(0, middle.indexOf("\n"));
    	}

        public void check_cert() {
            String path = currentProgram.getExecutablePath();
            String stdout = "";
            String stderr = "";
            String command = "";
            String serial = "";
            String Encoded = "";
            Boolean isWindows = false;
            File f = new File(path);
            if (!f.exists()) { //for whatever reason :)
                popup("Something went wrong while processing this file");
                return;
            }
            
            if (System.getProperty("os.name").toLowerCase().contains("win")) {
            	isWindows = true;
            	command = "powershell.exe (Get-AuthenticodeSignature '" + f.getPath() + "').SignerCertificate.SerialNumber";
            } else { 
            	command = "osslsigncode verify -in " + f.getPath() + " -CAfile /dev/null";
            }
            
            Process shellProcess;
            try {
                shellProcess = Runtime.getRuntime().exec(command);
                shellProcess.getOutputStream().close();
                stdout = IOUtils.toString(shellProcess.getInputStream(), StandardCharsets.UTF_8).trim();
                stderr = IOUtils.toString(shellProcess.getErrorStream(), StandardCharsets.UTF_8).trim();
            } catch (IOException e) {
                popup("Something went wrong while processing this file");
                return;
            }

            if (!stderr.isEmpty() || stdout.isEmpty()) {
                popup("Something went wrong while processing this file.");
                return;
            }
            
            if(isWindows) { 
            	 if(stdout.matches("^[0-9a-fA-F]+$")) { 
            		 serial = stdout;
            	 }
            	 
            } else { 
            	try { 
            		serial = GetSerial(stdout);
            	} catch (Exception e) { 
            		popup(e.getMessage());
            	}
            }
            
            if(serial.isEmpty()) { 
            	popup("Something went wrong while processing this file");
                return;
            }

            try {
                Encoded = URLEncoder.encode(":\"" + serial + "\"", StandardCharsets.UTF_8.toString());
            } catch (UnsupportedEncodingException e1) {
                popup("Error encounted while submitting data to VT.");
                e1.printStackTrace();
            }

            String url = "https://www.virustotal.com/gui/search/signature" + Encoded + "/files";
            OpenBrowser(url);


        }

        private void gen_imphash() throws IOException {
            String imports = "";
            String lib = "";
            String imphash = "";
            String func = "";
            Memory memory = currentProgram.getMemory();
            Address baseAddr = memory.getMinAddress();

            ByteProvider provider = new MemoryByteProvider(memory, baseAddr);

            PortableExecutable pe = null;

            try {
                pe = PortableExecutable.createPortableExecutable(RethrowContinuesFactory.INSTANCE, provider, SectionLayout.MEMORY, false, false);
            } catch (Exception e) {
                popup("Unable to create PE from current program");
                provider.close();
                return;
            }


            NTHeader nth = pe.getNTHeader();
            if (nth == null) {
                popup("NT Header not found");
                provider.close();
                return;
            }


            OptionalHeader oph = nth.getOptionalHeader();
            if (oph == null) {
                popup("OP Header not found");
                provider.close();
                return;
            }


            try {
                oph.processDataDirectories(monitor);
            } catch (Exception e) {
                System.out.println("only partial results!");
            }

            DataDirectory[] datadirs = oph.getDataDirectories();


            if (datadirs == null) {
                popup("Could not find any data directories");
                provider.close();
                return;
            }

            ImportDataDirectory idd = (ImportDataDirectory) datadirs[1];

            if (idd == null) {
                popup("Could not find the import dir");
                provider.close();
                return;
            }


            if (!idd.parse()) {
                popup("Could not parse import dir");
                provider.close();
                return;
            }

            ImportInfo[] import_entries = idd.getImports();

            if (import_entries.length == 0) {
                popup("No imports found!");
                provider.close();
                return;
            }


            for (int i = 0; i < import_entries.length; i++) {
                lib = import_entries[i].getDLL().toLowerCase();
                func = import_entries[i].getName().toLowerCase();
                if (lib.endsWith(".dll") || lib.endsWith(".sys") || lib.endsWith(".ocx")) {
                    lib = lib.split("\\.")[0];
                }

                if (Maps.maps.containsKey(lib)) {
                    func = Maps.maps.get(lib).get(func).toLowerCase();
                } else {
                    func = func.replaceAll("ordinal_", "ord");
                }

                imports += lib + "." + func;

                imports += (i != import_entries.length - 1 ? "," : "");
            }
            imphash = MD5Utilities.getMD5Hash(new ByteArrayInputStream(imports.getBytes(StandardCharsets.UTF_8)));

            try {
                imphash = URLEncoder.encode(":\"" + imphash + "\"", StandardCharsets.UTF_8.toString());
            } catch (UnsupportedEncodingException e1) {
                popup("Error encounted while submitting data to VT.");
                e1.printStackTrace();
            }

            String url = "https://www.virustotal.com/gui/search/imphash" + imphash + "/files";
            OpenBrowser(url);


        }

        private void OpenBrowser(String URL) {
            if (Desktop.isDesktopSupported()) {
                Desktop desktop = Desktop.getDesktop();
                try {
                    desktop.browse(new URI(URL));
                } catch (IOException | URISyntaxException e) {
                    popup("Error!");
                }
            } else {
                Runtime runtime = Runtime.getRuntime();
                try {
                    runtime.exec("xdg-open " + URL);
                } catch (IOException e) {
                    popup("Error encountered while searching VT");
                }
            }
        }

        @Override
        protected JPanel createWorkPanel() {

            // Create the main text area and give it a scroll bar.
            yaraTA = new JTextArea(12, 0);
            scrollPane = new JScrollPane(yaraTA);
            yaraTA.setWrapStyleWord(true);
            yaraTA.setLineWrap(true);

            // Create the instruction table and set it as a listener of the table model, so
            // this gui will be notified when changes have been made (when the user has adjusted
            // the mask settings).  This allows us to dynamically update the yara string as
            // the user is changing things.
            InstructionTablePanel instructionTablePanel =
                    new InstructionTablePanel(searchData.getMaxNumOperands(), plugin, this);
            instructionTablePanel.getTable().getModel().addTableModelListener(e -> {
                generateYara();
            });


            Icon VTscaledIcon = ResourceManager.getScaledIcon(ResourceManager.loadImage("images/magnifier.png"), 16, 16);
            Action actionVT = new SearchVTAction("VTgrep", VTscaledIcon, "Search using VTgrep", instructionTablePanel.getTable());


            EmptyBorderButton VTButton = new EmptyBorderButton();
            VTButton.setAction(actionVT);
            VTButton.setName("VTgrep");
            VTButton.setHideActionText(true);
            instructionTablePanel.getTable().getToolbar().add(VTButton);
            
            

            Icon SimilarIcon = ResourceManager.getScaledIcon(ResourceManager.loadImage("images/checkmark_green.gif"), 16, 16);
            Action actionSimilarCheck = new SimilarAction("SimilarCheck", SimilarIcon, "Generate Similar Query", instructionTablePanel.getTable());


            EmptyBorderButton SimilarButton = new EmptyBorderButton();
            SimilarButton.setAction(actionSimilarCheck);
            SimilarButton.setName("VTgrep");
            SimilarButton.setHideActionText(true);
            instructionTablePanel.getTable().getToolbar().add(SimilarButton);

            Icon StrictIcon = ResourceManager.getScaledIcon(ResourceManager.loadImage("images/notes.gif"), 16, 16);
            Action actionStrictCheck = new StrictAction("StrictCheck", StrictIcon, "Generate Similar Query (Strict)", instructionTablePanel.getTable());


            EmptyBorderButton StrictButton = new EmptyBorderButton();
            StrictButton.setAction(actionStrictCheck);
            StrictButton.setName("VTgrep");
            StrictButton.setHideActionText(true);
            instructionTablePanel.getTable().getToolbar().add(StrictButton);


            Icon CertIcon = ResourceManager.getScaledIcon(ResourceManager.loadImage("images/key.png"), 16, 16);
            Action actionCertCheck = new CertAction("CertCheck", CertIcon, "Find files signed by the same certificate", instructionTablePanel.getTable());


            EmptyBorderButton CertButton = new EmptyBorderButton();
            CertButton.setAction(actionCertCheck);
            CertButton.setName("VTgrep");
            CertButton.setHideActionText(true);
            instructionTablePanel.getTable().getToolbar().add(CertButton);


            Icon ImpHashIcon = ResourceManager.getScaledIcon(ResourceManager.loadImage("images/pencil.png"), 16, 16);
            Action actionImpHashCheck = new ImpHashAction("ImpHashCheck", ImpHashIcon, "Search by ImpHash", instructionTablePanel.getTable());


            EmptyBorderButton ImpHashButton = new EmptyBorderButton();
            ImpHashButton.setAction(actionImpHashCheck);
            ImpHashButton.setName("VTgrep");
            ImpHashButton.setHideActionText(true);
            instructionTablePanel.getTable().getToolbar().add(ImpHashButton);

            Icon MultiIcon = ResourceManager.getScaledIcon(ResourceManager.loadImage("images/unknown.gif"), 16, 16);
            Action actionMultiCheck = new MultiAction("MultiCheck", MultiIcon, "find similar files by different approaches", instructionTablePanel.getTable());


            EmptyBorderButton MultiButton = new EmptyBorderButton();
            MultiButton.setAction(actionMultiCheck);
            MultiButton.setName("VTgrep");
            MultiButton.setHideActionText(true);
            instructionTablePanel.getTable().getToolbar().add(MultiButton);


            JPanel mainPanel = new JPanel();
            mainPanel.setLayout(new BorderLayout());
            verticalSplitter = new JSplitPane(JSplitPane.VERTICAL_SPLIT, instructionTablePanel.getWorkPanel(), scrollPane);
            mainPanel.add(verticalSplitter);


            searchData.registerForGuiUpdates(instructionTablePanel.getTable());
            verticalSplitter.setDividerLocation(splitterSave);
            
            instructionTablePanel.getTable().getToolbar().remove(7);
            instructionTablePanel.getTable().getToolbar().remove(8);
            
            /*Component[] components = instructionTablePanel.getTable().getToolbar().getComponents();
            for(Component component : components) { 
            	if(component.getName() != null && component.getName().equals("manual entry")) { 
            		instructionTablePanel.getTable().getToolbar().remove(component);
            		break;
            	}
            }*/

            return mainPanel;
        }

        private void generateYara() {
            try {
                yaraTA.setText(generateYaraString("<insert name>"));
            } catch (Exception e1) {
                Msg.error(this, "Error generating yara string: " + e1);
            }
        }

        @Override
        public void update(Observable o, Object arg) {

            // Before rebuilding the UI, remember the splitter location so we can reset it
            // afterwards.
            if (verticalSplitter != null) {
                splitterSave = verticalSplitter.getDividerLocation();
            }

            if (arg instanceof UpdateType) {
                UpdateType type = (UpdateType) arg;
                switch (type) {
                    case RELOAD:
                        revalidate();
                        break;
                    case UPDATE:
                        // do nothing
                }
            }
        }

        public ArrayList<Slice> generate_slices(String[] sslices) {
            ArrayList<Slice> slices = new ArrayList<Slice>();
            for (String sslice : sslices) {
                if (sslice.contains("?")) {
                    slices.add(new Wildcards(sslice));
                } else {
                    slices.add(new Bytes(sslice));
                }
            }

            return slices;

        }

        public ArrayList<Slice> reduce_query(String str) {

            ArrayList<Slice> query_slices = generate_slices(str.split(" "));
            ArrayList<Slice> reduced_list = new ArrayList<Slice>();

            int prev = 0;
            for (Slice current : query_slices) {
                if (reduced_list.isEmpty()) {
                    reduced_list.add(current);
                } else {
                    prev = reduced_list.size() - 1;
                    if (reduced_list.get(prev).combinable(current)) {
                        reduced_list.set(prev, reduced_list.get(prev).combine(current));
                    } else {
                        reduced_list.add(current);
                    }
                }
            }

            return reduced_list;
        }

        public String sanitize(ArrayList<Slice> query) {

            boolean Modified = true;
            String outputSTR = "";
            int query_len;
            int qslice_index;
            int next_qslice_index;
            Slice next_qslice;
            Slice qslice;

            while (Modified) {
                Modified = false;
                query_len = query.size();
                qslice_index = 0;

                for (; qslice_index < query_len; qslice_index++) {
                    next_qslice_index = qslice_index + 1;
                    if (next_qslice_index != query_len) {
                        next_qslice = query.get(next_qslice_index);
                        qslice = check_combinable_and_combine(query.get(qslice_index), next_qslice);
                        if (qslice != null) {
                            query.set(qslice_index, qslice);
                            query.remove(next_qslice_index);
                            Modified = true;
                            break;
                        }
                    } else {
                        if (check_combinable_and_combine(query.get(qslice_index), null) != null) {
                            query.remove(qslice_index);
                            Modified = true;
                            break;
                        }
                    }
                }
            }
            for (Slice curr : query) {
                outputSTR += curr.get();
            }

            return outputSTR;
        }

        public Slice check_combinable_and_combine(Slice slice, Slice next_slice) {
            if (slice.combinable(next_slice)) {
                return slice.combine(next_slice);
            }

            return null;
        }

        @Override
        protected void revalidate() {
            removeWorkPanel();
            addWorkPanel(createWorkPanel());
            generateYara();
        }

        private class SearchVTAction extends AbstractAction {
            InstructionTable instructionTable;

            public SearchVTAction(String text, Icon icon, String desc, InstructionTable instructionTable) {
                super(text, icon);
                putValue(SHORT_DESCRIPTION, desc);
                this.instructionTable = instructionTable;
            }

            @Override
            public void actionPerformed(ActionEvent e) {

                String toURL = sanitize(reduce_query(currentSTR));

                if (toURL.length() < MIN_QUERY_LEN || toURL.length() > MAX_QUERY_LEN) {
                    popup("Error! minimum bytes query length should be at least " + MIN_QUERY_LEN + " and below " + MAX_QUERY_LEN + "!");
                    return;
                }

                dialog = new InstructionSearchDialog(plugin, "VT Search", null);
                try {
                    toURL = URLEncoder.encode(":{ " + toURL + " }", StandardCharsets.UTF_8.toString());
                } catch (UnsupportedEncodingException e1) {
                    popup("Error encounted while submitting data to VT.");
                    e1.printStackTrace();
                }
                String url = "https://www.virustotal.com/gui/search/content" + toURL + "/files";
                OpenBrowser(url);
                InstructionTableModel model = (InstructionTableModel) this.instructionTable.getModel();
                model.fireTableDataChanged();
            }
        }

        private class SimilarAction extends AbstractAction {
            InstructionTable instructionTable;

            public SimilarAction(String text, Icon icon, String desc, InstructionTable instructionTable) {
                super(text, icon);
                putValue(SHORT_DESCRIPTION, desc);
                this.instructionTable = instructionTable;
            }

            @Override
            public void actionPerformed(ActionEvent e) {

                for (int i = 0; i < this.instructionTable.getRowCount(); i++) {
                    for (int j = 0; j < this.instructionTable.getColumnCount(); j++) {
                        InstructionTableDataObject obj = this.instructionTable.getCellData(i, j);
                        if (obj == null || obj.getOperandCase() == null) {
                            continue;
                        }
                        if (OperandType.isDataReference(obj.getOperandCase().getOpType()) || OperandType.isScalar(obj.getOperandCase().getOpType()) || (OperandType.isCodeReference(obj.getOperandCase().getOpType()) && !OperandType.isRelative(obj.getOperandCase().getOpType()))) {
                            obj.setState(OperandState.MASKED, false);
                        }


                    }
                }

                InstructionTableModel model = (InstructionTableModel) this.instructionTable.getModel();
                model.fireTableDataChanged();
            }

        }

        private class StrictAction extends AbstractAction {
            InstructionTable instructionTable;

            public StrictAction(String text, Icon icon, String desc, InstructionTable instructionTable) {
                super(text, icon);
                putValue(SHORT_DESCRIPTION, desc);
                this.instructionTable = instructionTable;
            }

            @Override
            public void actionPerformed(ActionEvent e) {

                for (int i = 0; i < this.instructionTable.getRowCount(); i++) {
                    for (int j = 0; j < this.instructionTable.getColumnCount(); j++) {
                        InstructionTableDataObject obj = this.instructionTable.getCellData(i, j);
                        if (obj == null || obj.getOperandCase() == null) {
                            continue;
                        }
                        if (OperandType.isAddress(obj.getOperandCase().getOpType()) || OperandType.isDataReference(obj.getOperandCase().getOpType()) || OperandType.isScalar(obj.getOperandCase().getOpType()) || OperandType.isImmediate(obj.getOperandCase().getOpType()) || (OperandType.isCodeReference(obj.getOperandCase().getOpType()) && !OperandType.isRelative(obj.getOperandCase().getOpType()))) {
                            obj.setState(OperandState.MASKED, false);
                        }


                    }
                }

                InstructionTableModel model = (InstructionTableModel) this.instructionTable.getModel();
                model.fireTableDataChanged();
            }

        }

        private class CertAction extends AbstractAction {
            InstructionTable instructionTable;

            public CertAction(String text, Icon icon, String desc, InstructionTable instructionTable) {
                super(text, icon);
                putValue(SHORT_DESCRIPTION, desc);
                this.instructionTable = instructionTable;
            }

            @Override
            public void actionPerformed(ActionEvent e) {

                check_cert();

                InstructionTableModel model = (InstructionTableModel) this.instructionTable.getModel();
                model.fireTableDataChanged();
            }

        }

        private class ImpHashAction extends AbstractAction {
            InstructionTable instructionTable;

            public ImpHashAction(String text, Icon icon, String desc, InstructionTable instructionTable) {
                super(text, icon);
                putValue(SHORT_DESCRIPTION, desc);
                this.instructionTable = instructionTable;
            }

            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    gen_imphash();
                } catch (IOException e1) {
                    popup("Something went wrong while trying to calculate IMPHASH.");
                    e1.printStackTrace();
                }
                InstructionTableModel model = (InstructionTableModel) this.instructionTable.getModel();
                model.fireTableDataChanged();
            }

        }

        private class MultiAction extends AbstractAction {
            InstructionTable instructionTable;

            public MultiAction(String text, Icon icon, String desc, InstructionTable instructionTable) {
                super(text, icon);
                putValue(SHORT_DESCRIPTION, desc);
                this.instructionTable = instructionTable;
            }

            @Override
            public void actionPerformed(ActionEvent e) {
                String url = "https://www.virustotal.com/gui/search/similar-to:" + currentProgram.getExecutableSHA256() + "/files";
                OpenBrowser(url);
                InstructionTableModel model = (InstructionTableModel) this.instructionTable.getModel();
                model.fireTableDataChanged();
            }

        }
    }

    static class Bytes implements Slice {
        private String bytes_stream;

        public Bytes(String str) {
            this.bytes_stream = str;
        }

        public void append(Slice qslice) {
            this.bytes_stream += qslice.get();
        }

        public String get() {
            return this.bytes_stream;
        }

        public int len() {
            return this.bytes_stream.length();
        }


        public boolean combinable(Slice next_qslice) {
            if (next_qslice != null) {
                return !(next_qslice instanceof Wildcards) || this.len() < 8;
            } else return this.len() < 8;
        }

        public Slice combine(Slice next_qslice) {
            Slice wcs_stream;
            if (next_qslice != null) {
                if (next_qslice instanceof Bytes) {
                    this.append(next_qslice);
                    return this;
                }
                wcs_stream = this.mask();
                next_qslice.append(wcs_stream);
                return next_qslice;
            }
            return this;
        }

        public Slice mask() {
            return new Bytes("?".repeat(this.len()));
        }

        public boolean canCombine() {
            return !(this.len() >= 8);
        }

    }

    static class Wildcards implements Slice {
        private String wcs_stream;
        private boolean packed = false;

        public Wildcards(String str) {
            this.wcs_stream = str;
            this.pack();
        }

        public void append(Slice qslice) {
            int wcs_len;
            int wcs_count;
            if (!this.packed && !(qslice instanceof Wildcards)) {
                this.wcs_stream += qslice.get();
                this.pack();
            } else {
                wcs_len = this.len() + qslice.len();
                wcs_count = wcs_len / 2;
                this.wcs_stream = "[" + wcs_count + "]" + "?".repeat(wcs_len % 2);
                this.packed = true;
            }
        }

        public String get() {
            return this.wcs_stream;
        }

        public int len() {
            int str_len = 0;
            String wcs_len;
            int question_index;

            if (this.packed) {
                wcs_len = this.wcs_stream.replaceAll("^\\[", "").replaceAll("\\]$", "");
                question_index = this.wcs_stream.indexOf("?");
                if (question_index != -1) {
                    str_len = Integer.parseInt(wcs_len.replaceAll("\\]?$", "")) * 2;
                    str_len++;
                } else {
                    str_len = Integer.parseInt(wcs_len) * 2;
                }

                return str_len;

            }
            return this.wcs_stream.length();
        }

        private void pack() {
            int wcs_len;
            int wcs_count;
            if (!this.packed) {
                wcs_len = this.wcs_stream.length();
                if (wcs_len > 3) {
                    wcs_count = (wcs_len / 2);
                    this.wcs_stream = "[" + wcs_count + "]" + "?".repeat(wcs_len % 2);
                    this.packed = true;
                }
            }
        }

        public boolean combinable(Slice next_slice) {
            if (next_slice != null) {
                return next_slice.canCombine();
            }
            return true;
        }

        public Slice combine(Slice next_slice) {
            if (next_slice != null) {
                this.append(next_slice.mask());

            }
            return this;
        }

        public Slice mask() {
            return this;
        }

        public boolean canCombine() {
            return true;
        }

    }

	public static final class Maps { // this should be a part of GHIDRA tho, but o well...
		public static final Map<String, String> oleaut32;
		public static final Map<String, String> ws2_32;
		public static final Map<String, Map<String, String>> maps;

		static {
			oleaut32 = new HashMap<>();
			oleaut32.put("ordinal_2", "SysAllocString");
			oleaut32.put("ordinal_3", "SysReAllocString");
			oleaut32.put("ordinal_4", "SysAllocStringLen");
			oleaut32.put("ordinal_5", "SysReAllocStringLen");
			oleaut32.put("ordinal_6", "SysFreeString");
			oleaut32.put("ordinal_7", "SysStringLen");
			oleaut32.put("ordinal_8", "VariantInit");
			oleaut32.put("ordinal_9", "VariantClear");
			oleaut32.put("ordinal_10", "VariantCopy");
			oleaut32.put("ordinal_11", "VariantCopyInd");
			oleaut32.put("ordinal_12", "VariantChangeType");
			oleaut32.put("ordinal_13", "VariantTimeToDosDateTime");
			oleaut32.put("ordinal_14", "DosDateTimeToVariantTime");
			oleaut32.put("ordinal_15", "SafeArrayCreate");
			oleaut32.put("ordinal_16", "SafeArrayDestroy");
			oleaut32.put("ordinal_17", "SafeArrayGetDim");
			oleaut32.put("ordinal_18", "SafeArrayGetElemsize");
			oleaut32.put("ordinal_19", "SafeArrayGetUBound");
			oleaut32.put("ordinal_20", "SafeArrayGetLBound");
			oleaut32.put("ordinal_21", "SafeArrayLock");
			oleaut32.put("ordinal_22", "SafeArrayUnlock");
			oleaut32.put("ordinal_23", "SafeArrayAccessData");
			oleaut32.put("ordinal_24", "SafeArrayUnaccessData");
			oleaut32.put("ordinal_25", "SafeArrayGetElement");
			oleaut32.put("ordinal_26", "SafeArrayPutElement");
			oleaut32.put("ordinal_27", "SafeArrayCopy");
			oleaut32.put("ordinal_28", "DispGetParam");
			oleaut32.put("ordinal_29", "DispGetIDsOfNames");
			oleaut32.put("ordinal_30", "DispInvoke");
			oleaut32.put("ordinal_31", "CreateDispTypeInfo");
			oleaut32.put("ordinal_32", "CreateStdDispatch");
			oleaut32.put("ordinal_33", "RegisterActiveObject");
			oleaut32.put("ordinal_34", "RevokeActiveObject");
			oleaut32.put("ordinal_35", "GetActiveObject");
			oleaut32.put("ordinal_36", "SafeArrayAllocDescriptor");
			oleaut32.put("ordinal_37", "SafeArrayAllocData");
			oleaut32.put("ordinal_38", "SafeArrayDestroyDescriptor");
			oleaut32.put("ordinal_39", "SafeArrayDestroyData");
			oleaut32.put("ordinal_40", "SafeArrayRedim");
			oleaut32.put("ordinal_41", "SafeArrayAllocDescriptorEx");
			oleaut32.put("ordinal_42", "SafeArrayCreateEx");
			oleaut32.put("ordinal_43", "SafeArrayCreateVectorEx");
			oleaut32.put("ordinal_44", "SafeArraySetRecordInfo");
			oleaut32.put("ordinal_45", "SafeArrayGetRecordInfo");
			oleaut32.put("ordinal_46", "VarParseNumFromStr");
			oleaut32.put("ordinal_47", "VarNumFromParseNum");
			oleaut32.put("ordinal_48", "VarI2FromUI1");
			oleaut32.put("ordinal_49", "VarI2FromI4");
			oleaut32.put("ordinal_50", "VarI2FromR4");
			oleaut32.put("ordinal_51", "VarI2FromR8");
			oleaut32.put("ordinal_52", "VarI2FromCy");
			oleaut32.put("ordinal_53", "VarI2FromDate");
			oleaut32.put("ordinal_54", "VarI2FromStr");
			oleaut32.put("ordinal_55", "VarI2FromDisp");
			oleaut32.put("ordinal_56", "VarI2FromBool");
			oleaut32.put("ordinal_57", "SafeArraySetIID");
			oleaut32.put("ordinal_58", "VarI4FromUI1");
			oleaut32.put("ordinal_59", "VarI4FromI2");
			oleaut32.put("ordinal_60", "VarI4FromR4");
			oleaut32.put("ordinal_61", "VarI4FromR8");
			oleaut32.put("ordinal_62", "VarI4FromCy");
			oleaut32.put("ordinal_63", "VarI4FromDate");
			oleaut32.put("ordinal_64", "VarI4FromStr");
			oleaut32.put("ordinal_65", "VarI4FromDisp");
			oleaut32.put("ordinal_66", "VarI4FromBool");
			oleaut32.put("ordinal_67", "SafeArrayGetIID");
			oleaut32.put("ordinal_68", "VarR4FromUI1");
			oleaut32.put("ordinal_69", "VarR4FromI2");
			oleaut32.put("ordinal_70", "VarR4FromI4");
			oleaut32.put("ordinal_71", "VarR4FromR8");
			oleaut32.put("ordinal_72", "VarR4FromCy");
			oleaut32.put("ordinal_73", "VarR4FromDate");
			oleaut32.put("ordinal_74", "VarR4FromStr");
			oleaut32.put("ordinal_75", "VarR4FromDisp");
			oleaut32.put("ordinal_76", "VarR4FromBool");
			oleaut32.put("ordinal_77", "SafeArrayGetVartype");
			oleaut32.put("ordinal_78", "VarR8FromUI1");
			oleaut32.put("ordinal_79", "VarR8FromI2");
			oleaut32.put("ordinal_80", "VarR8FromI4");
			oleaut32.put("ordinal_81", "VarR8FromR4");
			oleaut32.put("ordinal_82", "VarR8FromCy");
			oleaut32.put("ordinal_83", "VarR8FromDate");
			oleaut32.put("ordinal_84", "VarR8FromStr");
			oleaut32.put("ordinal_85", "VarR8FromDisp");
			oleaut32.put("ordinal_86", "VarR8FromBool");
			oleaut32.put("ordinal_87", "VarFormat");
			oleaut32.put("ordinal_88", "VarDateFromUI1");
			oleaut32.put("ordinal_89", "VarDateFromI2");
			oleaut32.put("ordinal_90", "VarDateFromI4");
			oleaut32.put("ordinal_91", "VarDateFromR4");
			oleaut32.put("ordinal_92", "VarDateFromR8");
			oleaut32.put("ordinal_93", "VarDateFromCy");
			oleaut32.put("ordinal_94", "VarDateFromStr");
			oleaut32.put("ordinal_95", "VarDateFromDisp");
			oleaut32.put("ordinal_96", "VarDateFromBool");
			oleaut32.put("ordinal_97", "VarFormatDateTime");
			oleaut32.put("ordinal_98", "VarCyFromUI1");
			oleaut32.put("ordinal_99", "VarCyFromI2");
			oleaut32.put("ordinal_100", "VarCyFromI4");
			oleaut32.put("ordinal_101", "VarCyFromR4");
			oleaut32.put("ordinal_102", "VarCyFromR8");
			oleaut32.put("ordinal_103", "VarCyFromDate");
			oleaut32.put("ordinal_104", "VarCyFromStr");
			oleaut32.put("ordinal_105", "VarCyFromDisp");
			oleaut32.put("ordinal_106", "VarCyFromBool");
			oleaut32.put("ordinal_107", "VarFormatNumber");
			oleaut32.put("ordinal_108", "VarBstrFromUI1");
			oleaut32.put("ordinal_109", "VarBstrFromI2");
			oleaut32.put("ordinal_110", "VarBstrFromI4");
			oleaut32.put("ordinal_111", "VarBstrFromR4");
			oleaut32.put("ordinal_112", "VarBstrFromR8");
			oleaut32.put("ordinal_113", "VarBstrFromCy");
			oleaut32.put("ordinal_114", "VarBstrFromDate");
			oleaut32.put("ordinal_115", "VarBstrFromDisp");
			oleaut32.put("ordinal_116", "VarBstrFromBool");
			oleaut32.put("ordinal_117", "VarFormatPercent");
			oleaut32.put("ordinal_118", "VarBoolFromUI1");
			oleaut32.put("ordinal_119", "VarBoolFromI2");
			oleaut32.put("ordinal_120", "VarBoolFromI4");
			oleaut32.put("ordinal_121", "VarBoolFromR4");
			oleaut32.put("ordinal_122", "VarBoolFromR8");
			oleaut32.put("ordinal_123", "VarBoolFromDate");
			oleaut32.put("ordinal_124", "VarBoolFromCy");
			oleaut32.put("ordinal_125", "VarBoolFromStr");
			oleaut32.put("ordinal_126", "VarBoolFromDisp");
			oleaut32.put("ordinal_127", "VarFormatCurrency");
			oleaut32.put("ordinal_128", "VarWeekdayName");
			oleaut32.put("ordinal_129", "VarMonthName");
			oleaut32.put("ordinal_130", "VarUI1FromI2");
			oleaut32.put("ordinal_131", "VarUI1FromI4");
			oleaut32.put("ordinal_132", "VarUI1FromR4");
			oleaut32.put("ordinal_133", "VarUI1FromR8");
			oleaut32.put("ordinal_134", "VarUI1FromCy");
			oleaut32.put("ordinal_135", "VarUI1FromDate");
			oleaut32.put("ordinal_136", "VarUI1FromStr");
			oleaut32.put("ordinal_137", "VarUI1FromDisp");
			oleaut32.put("ordinal_138", "VarUI1FromBool");
			oleaut32.put("ordinal_139", "VarFormatFromTokens");
			oleaut32.put("ordinal_140", "VarTokenizeFormatString");
			oleaut32.put("ordinal_141", "VarAdd");
			oleaut32.put("ordinal_142", "VarAnd");
			oleaut32.put("ordinal_143", "VarDiv");
			oleaut32.put("ordinal_144", "DllCanUnloadNow");
			oleaut32.put("ordinal_145", "DllGetClassObject");
			oleaut32.put("ordinal_146", "DispCallFunc");
			oleaut32.put("ordinal_147", "VariantChangeTypeEx");
			oleaut32.put("ordinal_148", "SafeArrayPtrOfIndex");
			oleaut32.put("ordinal_149", "SysStringByteLen");
			oleaut32.put("ordinal_150", "SysAllocStringByteLen");
			oleaut32.put("ordinal_151", "DllRegisterServer");
			oleaut32.put("ordinal_152", "VarEqv");
			oleaut32.put("ordinal_153", "VarIdiv");
			oleaut32.put("ordinal_154", "VarImp");
			oleaut32.put("ordinal_155", "VarMod");
			oleaut32.put("ordinal_156", "VarMul");
			oleaut32.put("ordinal_157", "VarOr");
			oleaut32.put("ordinal_158", "VarPow");
			oleaut32.put("ordinal_159", "VarSu");
			oleaut32.put("ordinal_160", "CreateTypeLi");
			oleaut32.put("ordinal_161", "LoadTypeLi");
			oleaut32.put("ordinal_162", "LoadRegTypeLi");
			oleaut32.put("ordinal_163", "RegisterTypeLi");
			oleaut32.put("ordinal_164", "QueryPathOfRegTypeLi");
			oleaut32.put("ordinal_165", "LHashValOfNameSys");
			oleaut32.put("ordinal_166", "LHashValOfNameSysA");
			oleaut32.put("ordinal_167", "VarXor");
			oleaut32.put("ordinal_168", "VarAbs");
			oleaut32.put("ordinal_169", "VarFix");
			oleaut32.put("ordinal_170", "OaBuildVersion");
			oleaut32.put("ordinal_171", "ClearCustData");
			oleaut32.put("ordinal_172", "VarInt");
			oleaut32.put("ordinal_173", "VarNeg");
			oleaut32.put("ordinal_174", "VarNot");
			oleaut32.put("ordinal_175", "VarRound");
			oleaut32.put("ordinal_176", "VarCmp");
			oleaut32.put("ordinal_177", "VarDecAdd");
			oleaut32.put("ordinal_178", "VarDecDiv");
			oleaut32.put("ordinal_179", "VarDecMul");
			oleaut32.put("ordinal_180", "CreateTypeLib2");
			oleaut32.put("ordinal_181", "VarDecSu");
			oleaut32.put("ordinal_182", "VarDecAbs");
			oleaut32.put("ordinal_183", "LoadTypeLibEx");
			oleaut32.put("ordinal_184", "SystemTimeToVariantTime");
			oleaut32.put("ordinal_185", "VariantTimeToSystemTime");
			oleaut32.put("ordinal_186", "UnRegisterTypeLi");
			oleaut32.put("ordinal_187", "VarDecFix");
			oleaut32.put("ordinal_188", "VarDecInt");
			oleaut32.put("ordinal_189", "VarDecNeg");
			oleaut32.put("ordinal_190", "VarDecFromUI1");
			oleaut32.put("ordinal_191", "VarDecFromI2");
			oleaut32.put("ordinal_192", "VarDecFromI4");
			oleaut32.put("ordinal_193", "VarDecFromR4");
			oleaut32.put("ordinal_194", "VarDecFromR8");
			oleaut32.put("ordinal_195", "VarDecFromDate");
			oleaut32.put("ordinal_196", "VarDecFromCy");
			oleaut32.put("ordinal_197", "VarDecFromStr");
			oleaut32.put("ordinal_198", "VarDecFromDisp");
			oleaut32.put("ordinal_199", "VarDecFromBool");
			oleaut32.put("ordinal_200", "GetErrorInfo");
			oleaut32.put("ordinal_201", "SetErrorInfo");
			oleaut32.put("ordinal_202", "CreateErrorInfo");
			oleaut32.put("ordinal_203", "VarDecRound");
			oleaut32.put("ordinal_204", "VarDecCmp");
			oleaut32.put("ordinal_205", "VarI2FromI1");
			oleaut32.put("ordinal_206", "VarI2FromUI2");
			oleaut32.put("ordinal_207", "VarI2FromUI4");
			oleaut32.put("ordinal_208", "VarI2FromDec");
			oleaut32.put("ordinal_209", "VarI4FromI1");
			oleaut32.put("ordinal_210", "VarI4FromUI2");
			oleaut32.put("ordinal_211", "VarI4FromUI4");
			oleaut32.put("ordinal_212", "VarI4FromDec");
			oleaut32.put("ordinal_213", "VarR4FromI1");
			oleaut32.put("ordinal_214", "VarR4FromUI2");
			oleaut32.put("ordinal_215", "VarR4FromUI4");
			oleaut32.put("ordinal_216", "VarR4FromDec");
			oleaut32.put("ordinal_217", "VarR8FromI1");
			oleaut32.put("ordinal_218", "VarR8FromUI2");
			oleaut32.put("ordinal_219", "VarR8FromUI4");
			oleaut32.put("ordinal_220", "VarR8FromDec");
			oleaut32.put("ordinal_221", "VarDateFromI1");
			oleaut32.put("ordinal_222", "VarDateFromUI2");
			oleaut32.put("ordinal_223", "VarDateFromUI4");
			oleaut32.put("ordinal_224", "VarDateFromDec");
			oleaut32.put("ordinal_225", "VarCyFromI1");
			oleaut32.put("ordinal_226", "VarCyFromUI2");
			oleaut32.put("ordinal_227", "VarCyFromUI4");
			oleaut32.put("ordinal_228", "VarCyFromDec");
			oleaut32.put("ordinal_229", "VarBstrFromI1");
			oleaut32.put("ordinal_230", "VarBstrFromUI2");
			oleaut32.put("ordinal_231", "VarBstrFromUI4");
			oleaut32.put("ordinal_232", "VarBstrFromDec");
			oleaut32.put("ordinal_233", "VarBoolFromI1");
			oleaut32.put("ordinal_234", "VarBoolFromUI2");
			oleaut32.put("ordinal_235", "VarBoolFromUI4");
			oleaut32.put("ordinal_236", "VarBoolFromDec");
			oleaut32.put("ordinal_237", "VarUI1FromI1");
			oleaut32.put("ordinal_238", "VarUI1FromUI2");
			oleaut32.put("ordinal_239", "VarUI1FromUI4");
			oleaut32.put("ordinal_240", "VarUI1FromDec");
			oleaut32.put("ordinal_241", "VarDecFromI1");
			oleaut32.put("ordinal_242", "VarDecFromUI2");
			oleaut32.put("ordinal_243", "VarDecFromUI4");
			oleaut32.put("ordinal_244", "VarI1FromUI1");
			oleaut32.put("ordinal_245", "VarI1FromI2");
			oleaut32.put("ordinal_246", "VarI1FromI4");
			oleaut32.put("ordinal_247", "VarI1FromR4");
			oleaut32.put("ordinal_248", "VarI1FromR8");
			oleaut32.put("ordinal_249", "VarI1FromDate");
			oleaut32.put("ordinal_250", "VarI1FromCy");
			oleaut32.put("ordinal_251", "VarI1FromStr");
			oleaut32.put("ordinal_252", "VarI1FromDisp");
			oleaut32.put("ordinal_253", "VarI1FromBool");
			oleaut32.put("ordinal_254", "VarI1FromUI2");
			oleaut32.put("ordinal_255", "VarI1FromUI4");
			oleaut32.put("ordinal_256", "VarI1FromDec");
			oleaut32.put("ordinal_257", "VarUI2FromUI1");
			oleaut32.put("ordinal_258", "VarUI2FromI2");
			oleaut32.put("ordinal_259", "VarUI2FromI4");
			oleaut32.put("ordinal_260", "VarUI2FromR4");
			oleaut32.put("ordinal_261", "VarUI2FromR8");
			oleaut32.put("ordinal_262", "VarUI2FromDate");
			oleaut32.put("ordinal_263", "VarUI2FromCy");
			oleaut32.put("ordinal_264", "VarUI2FromStr");
			oleaut32.put("ordinal_265", "VarUI2FromDisp");
			oleaut32.put("ordinal_266", "VarUI2FromBool");
			oleaut32.put("ordinal_267", "VarUI2FromI1");
			oleaut32.put("ordinal_268", "VarUI2FromUI4");
			oleaut32.put("ordinal_269", "VarUI2FromDec");
			oleaut32.put("ordinal_270", "VarUI4FromUI1");
			oleaut32.put("ordinal_271", "VarUI4FromI2");
			oleaut32.put("ordinal_272", "VarUI4FromI4");
			oleaut32.put("ordinal_273", "VarUI4FromR4");
			oleaut32.put("ordinal_274", "VarUI4FromR8");
			oleaut32.put("ordinal_275", "VarUI4FromDate");
			oleaut32.put("ordinal_276", "VarUI4FromCy");
			oleaut32.put("ordinal_277", "VarUI4FromStr");
			oleaut32.put("ordinal_278", "VarUI4FromDisp");
			oleaut32.put("ordinal_279", "VarUI4FromBool");
			oleaut32.put("ordinal_280", "VarUI4FromI1");
			oleaut32.put("ordinal_281", "VarUI4FromUI2");
			oleaut32.put("ordinal_282", "VarUI4FromDec");
			oleaut32.put("ordinal_283", "BSTR_UserSize");
			oleaut32.put("ordinal_284", "BSTR_UserMarshal");
			oleaut32.put("ordinal_285", "BSTR_UserUnmarshal");
			oleaut32.put("ordinal_286", "BSTR_UserFree");
			oleaut32.put("ordinal_287", "VARIANT_UserSize");
			oleaut32.put("ordinal_288", "VARIANT_UserMarshal");
			oleaut32.put("ordinal_289", "VARIANT_UserUnmarshal");
			oleaut32.put("ordinal_290", "VARIANT_UserFree");
			oleaut32.put("ordinal_291", "LPSAFEARRAY_UserSize");
			oleaut32.put("ordinal_292", "LPSAFEARRAY_UserMarshal");
			oleaut32.put("ordinal_293", "LPSAFEARRAY_UserUnmarshal");
			oleaut32.put("ordinal_294", "LPSAFEARRAY_UserFree");
			oleaut32.put("ordinal_295", "LPSAFEARRAY_Size");
			oleaut32.put("ordinal_296", "LPSAFEARRAY_Marshal");
			oleaut32.put("ordinal_297", "LPSAFEARRAY_Unmarshal");
			oleaut32.put("ordinal_298", "VarDecCmpR8");
			oleaut32.put("ordinal_299", "VarCyAdd");
			oleaut32.put("ordinal_300", "DllUnregisterServer");
			oleaut32.put("ordinal_301", "OACreateTypeLib2");
			oleaut32.put("ordinal_303", "VarCyMul");
			oleaut32.put("ordinal_304", "VarCyMulI4");
			oleaut32.put("ordinal_305", "VarCySu");
			oleaut32.put("ordinal_306", "VarCyAbs");
			oleaut32.put("ordinal_307", "VarCyFix");
			oleaut32.put("ordinal_308", "VarCyInt");
			oleaut32.put("ordinal_309", "VarCyNeg");
			oleaut32.put("ordinal_310", "VarCyRound");
			oleaut32.put("ordinal_311", "VarCyCmp");
			oleaut32.put("ordinal_312", "VarCyCmpR8");
			oleaut32.put("ordinal_313", "VarBstrCat");
			oleaut32.put("ordinal_314", "VarBstrCmp");
			oleaut32.put("ordinal_315", "VarR8Pow");
			oleaut32.put("ordinal_316", "VarR4CmpR8");
			oleaut32.put("ordinal_317", "VarR8Round");
			oleaut32.put("ordinal_318", "VarCat");
			oleaut32.put("ordinal_319", "VarDateFromUdateEx");
			oleaut32.put("ordinal_322", "GetRecordInfoFromGuids");
			oleaut32.put("ordinal_323", "GetRecordInfoFromTypeInfo");
			oleaut32.put("ordinal_325", "SetVarConversionLocaleSetting");
			oleaut32.put("ordinal_326", "GetVarConversionLocaleSetting");
			oleaut32.put("ordinal_327", "SetOaNoCache");
			oleaut32.put("ordinal_329", "VarCyMulI8");
			oleaut32.put("ordinal_330", "VarDateFromUdate");
			oleaut32.put("ordinal_331", "VarUdateFromDate");
			oleaut32.put("ordinal_332", "GetAltMonthNames");
			oleaut32.put("ordinal_333", "VarI8FromUI1");
			oleaut32.put("ordinal_334", "VarI8FromI2");
			oleaut32.put("ordinal_335", "VarI8FromR4");
			oleaut32.put("ordinal_336", "VarI8FromR8");
			oleaut32.put("ordinal_337", "VarI8FromCy");
			oleaut32.put("ordinal_338", "VarI8FromDate");
			oleaut32.put("ordinal_339", "VarI8FromStr");
			oleaut32.put("ordinal_340", "VarI8FromDisp");
			oleaut32.put("ordinal_341", "VarI8FromBool");
			oleaut32.put("ordinal_342", "VarI8FromI1");
			oleaut32.put("ordinal_343", "VarI8FromUI2");
			oleaut32.put("ordinal_344", "VarI8FromUI4");
			oleaut32.put("ordinal_345", "VarI8FromDec");
			oleaut32.put("ordinal_346", "VarI2FromI8");
			oleaut32.put("ordinal_347", "VarI2FromUI8");
			oleaut32.put("ordinal_348", "VarI4FromI8");
			oleaut32.put("ordinal_349", "VarI4FromUI8");
			oleaut32.put("ordinal_360", "VarR4FromI8");
			oleaut32.put("ordinal_361", "VarR4FromUI8");
			oleaut32.put("ordinal_362", "VarR8FromI8");
			oleaut32.put("ordinal_363", "VarR8FromUI8");
			oleaut32.put("ordinal_364", "VarDateFromI8");
			oleaut32.put("ordinal_365", "VarDateFromUI8");
			oleaut32.put("ordinal_366", "VarCyFromI8");
			oleaut32.put("ordinal_367", "VarCyFromUI8");
			oleaut32.put("ordinal_368", "VarBstrFromI8");
			oleaut32.put("ordinal_369", "VarBstrFromUI8");
			oleaut32.put("ordinal_370", "VarBoolFromI8");
			oleaut32.put("ordinal_371", "VarBoolFromUI8");
			oleaut32.put("ordinal_372", "VarUI1FromI8");
			oleaut32.put("ordinal_373", "VarUI1FromUI8");
			oleaut32.put("ordinal_374", "VarDecFromI8");
			oleaut32.put("ordinal_375", "VarDecFromUI8");
			oleaut32.put("ordinal_376", "VarI1FromI8");
			oleaut32.put("ordinal_377", "VarI1FromUI8");
			oleaut32.put("ordinal_378", "VarUI2FromI8");
			oleaut32.put("ordinal_379", "VarUI2FromUI8");
			oleaut32.put("ordinal_401", "OleLoadPictureEx");
			oleaut32.put("ordinal_402", "OleLoadPictureFileEx");
			oleaut32.put("ordinal_411", "SafeArrayCreateVector");
			oleaut32.put("ordinal_412", "SafeArrayCopyData");
			oleaut32.put("ordinal_413", "VectorFromBstr");
			oleaut32.put("ordinal_414", "BstrFromVector");
			oleaut32.put("ordinal_415", "OleIconToCursor");
			oleaut32.put("ordinal_416", "OleCreatePropertyFrameIndirect");
			oleaut32.put("ordinal_417", "OleCreatePropertyFrame");
			oleaut32.put("ordinal_418", "OleLoadPicture");
			oleaut32.put("ordinal_419", "OleCreatePictureIndirect");
			oleaut32.put("ordinal_420", "OleCreateFontIndirect");
			oleaut32.put("ordinal_421", "OleTranslateColor");
			oleaut32.put("ordinal_422", "OleLoadPictureFile");
			oleaut32.put("ordinal_423", "OleSavePictureFile");
			oleaut32.put("ordinal_424", "OleLoadPicturePath");
			oleaut32.put("ordinal_425", "VarUI4FromI8");
			oleaut32.put("ordinal_426", "VarUI4FromUI8");
			oleaut32.put("ordinal_427", "VarI8FromUI8");
			oleaut32.put("ordinal_428", "VarUI8FromI8");
			oleaut32.put("ordinal_429", "VarUI8FromUI1");
			oleaut32.put("ordinal_430", "VarUI8FromI2");
			oleaut32.put("ordinal_431", "VarUI8FromR4");
			oleaut32.put("ordinal_432", "VarUI8FromR8");
			oleaut32.put("ordinal_433", "VarUI8FromCy");
			oleaut32.put("ordinal_434", "VarUI8FromDate");
			oleaut32.put("ordinal_435", "VarUI8FromStr");
			oleaut32.put("ordinal_436", "VarUI8FromDisp");
			oleaut32.put("ordinal_437", "VarUI8FromBool");
			oleaut32.put("ordinal_438", "VarUI8FromI1");
			oleaut32.put("ordinal_439", "VarUI8FromUI2");
			oleaut32.put("ordinal_440", "VarUI8FromUI4");
			oleaut32.put("ordinal_441", "VarUI8FromDec");
			oleaut32.put("ordinal_442", "RegisterTypeLibForUser");
			oleaut32.put("ordinal_443", "UnRegisterTypeLibForUser");
		}

		static {
			ws2_32 = new HashMap<>();
			ws2_32.put("ordinal_1", "accept");
			ws2_32.put("ordinal_2", "bind");
			ws2_32.put("ordinal_3", "closesocket");
			ws2_32.put("ordinal_4", "connect");
			ws2_32.put("ordinal_5", "getpeername");
			ws2_32.put("ordinal_6", "getsockname");
			ws2_32.put("ordinal_7", "getsockopt");
			ws2_32.put("ordinal_8", "htonl");
			ws2_32.put("ordinal_9", "htons");
			ws2_32.put("ordinal_10", "ioctlsocket");
			ws2_32.put("ordinal_11", "inet_addr");
			ws2_32.put("ordinal_12", "inet_ntoa");
			ws2_32.put("ordinal_13", "listen");
			ws2_32.put("ordinal_14", "ntohl");
			ws2_32.put("ordinal_15", "ntohs");
			ws2_32.put("ordinal_16", "recv");
			ws2_32.put("ordinal_17", "recvfrom");
			ws2_32.put("ordinal_18", "select");
			ws2_32.put("ordinal_19", "send");
			ws2_32.put("ordinal_20", "sendto");
			ws2_32.put("ordinal_21", "setsockopt");
			ws2_32.put("ordinal_22", "shutdown");
			ws2_32.put("ordinal_23", "socket");
			ws2_32.put("ordinal_24", "GetAddrInfoW");
			ws2_32.put("ordinal_25", "GetNameInfoW");
			ws2_32.put("ordinal_26", "WSApSetPostRoutine");
			ws2_32.put("ordinal_27", "FreeAddrInfoW");
			ws2_32.put("ordinal_28", "WPUCompleteOverlappedRequest");
			ws2_32.put("ordinal_29", "WSAAccept");
			ws2_32.put("ordinal_30", "WSAAddressToStringA");
			ws2_32.put("ordinal_31", "WSAAddressToStringW");
			ws2_32.put("ordinal_32", "WSACloseEvent");
			ws2_32.put("ordinal_33", "WSAConnect");
			ws2_32.put("ordinal_34", "WSACreateEvent");
			ws2_32.put("ordinal_35", "WSADuplicateSocketA");
			ws2_32.put("ordinal_36", "WSADuplicateSocketW");
			ws2_32.put("ordinal_37", "WSAEnumNameSpaceProvidersA");
			ws2_32.put("ordinal_38", "WSAEnumNameSpaceProvidersW");
			ws2_32.put("ordinal_39", "WSAEnumNetworkEvents");
			ws2_32.put("ordinal_40", "WSAEnumProtocolsA");
			ws2_32.put("ordinal_41", "WSAEnumProtocolsW");
			ws2_32.put("ordinal_42", "WSAEventSelect");
			ws2_32.put("ordinal_43", "WSAGetOverlappedResult");
			ws2_32.put("ordinal_44", "WSAGetQOSByName");
			ws2_32.put("ordinal_45", "WSAGetServiceClassInfoA");
			ws2_32.put("ordinal_46", "WSAGetServiceClassInfoW");
			ws2_32.put("ordinal_47", "WSAGetServiceClassNameByClassIdA");
			ws2_32.put("ordinal_48", "WSAGetServiceClassNameByClassIdW");
			ws2_32.put("ordinal_49", "WSAHtonl");
			ws2_32.put("ordinal_50", "WSAHtons");
			ws2_32.put("ordinal_51", "gethostbyaddr");
			ws2_32.put("ordinal_52", "gethostbyname");
			ws2_32.put("ordinal_53", "getprotobyname");
			ws2_32.put("ordinal_54", "getprotobynumber");
			ws2_32.put("ordinal_55", "getservbyname");
			ws2_32.put("ordinal_56", "getservbyport");
			ws2_32.put("ordinal_57", "gethostname");
			ws2_32.put("ordinal_58", "WSAInstallServiceClassA");
			ws2_32.put("ordinal_59", "WSAInstallServiceClassW");
			ws2_32.put("ordinal_60", "WSAIoctl");
			ws2_32.put("ordinal_61", "WSAJoinLeaf");
			ws2_32.put("ordinal_62", "WSALookupServiceBeginA");
			ws2_32.put("ordinal_63", "WSALookupServiceBeginW");
			ws2_32.put("ordinal_64", "WSALookupServiceEnd");
			ws2_32.put("ordinal_65", "WSALookupServiceNextA");
			ws2_32.put("ordinal_66", "WSALookupServiceNextW");
			ws2_32.put("ordinal_67", "WSANSPIoctl");
			ws2_32.put("ordinal_68", "WSANtohl");
			ws2_32.put("ordinal_69", "WSANtohs");
			ws2_32.put("ordinal_70", "WSAProviderConfigChange");
			ws2_32.put("ordinal_71", "WSARecv");
			ws2_32.put("ordinal_72", "WSARecvDisconnect");
			ws2_32.put("ordinal_73", "WSARecvFrom");
			ws2_32.put("ordinal_74", "WSARemoveServiceClass");
			ws2_32.put("ordinal_75", "WSAResetEvent");
			ws2_32.put("ordinal_76", "WSASend");
			ws2_32.put("ordinal_77", "WSASendDisconnect");
			ws2_32.put("ordinal_78", "WSASendTo");
			ws2_32.put("ordinal_79", "WSASetEvent");
			ws2_32.put("ordinal_80", "WSASetServiceA");
			ws2_32.put("ordinal_81", "WSASetServiceW");
			ws2_32.put("ordinal_82", "WSASocketA");
			ws2_32.put("ordinal_83", "WSASocketW");
			ws2_32.put("ordinal_84", "WSAStringToAddressA");
			ws2_32.put("ordinal_85", "WSAStringToAddressW");
			ws2_32.put("ordinal_86", "WSAWaitForMultipleEvents");
			ws2_32.put("ordinal_87", "WSCDeinstallProvider");
			ws2_32.put("ordinal_88", "WSCEnableNSProvider");
			ws2_32.put("ordinal_89", "WSCEnumProtocols");
			ws2_32.put("ordinal_90", "WSCGetProviderPath");
			ws2_32.put("ordinal_91", "WSCInstallNameSpace");
			ws2_32.put("ordinal_92", "WSCInstallProvider");
			ws2_32.put("ordinal_93", "WSCUnInstallNameSpace");
			ws2_32.put("ordinal_94", "WSCUpdateProvider");
			ws2_32.put("ordinal_95", "WSCWriteNameSpaceOrder");
			ws2_32.put("ordinal_96", "WSCWriteProviderOrder");
			ws2_32.put("ordinal_97", "freeaddrinfo");
			ws2_32.put("ordinal_98", "getaddrinfo");
			ws2_32.put("ordinal_99", "getnameinfo");
			ws2_32.put("ordinal_101", "WSAAsyncSelect");
			ws2_32.put("ordinal_102", "WSAAsyncGetHostByAddr");
			ws2_32.put("ordinal_103", "WSAAsyncGetHostByName");
			ws2_32.put("ordinal_104", "WSAAsyncGetProtoByNumber");
			ws2_32.put("ordinal_105", "WSAAsyncGetProtoByName");
			ws2_32.put("ordinal_106", "WSAAsyncGetServByPort");
			ws2_32.put("ordinal_107", "WSAAsyncGetServByName");
			ws2_32.put("ordinal_108", "WSACancelAsyncRequest");
			ws2_32.put("ordinal_109", "WSASetBlockingHook");
			ws2_32.put("ordinal_110", "WSAUnhookBlockingHook");
			ws2_32.put("ordinal_111", "WSAGetLastError");
			ws2_32.put("ordinal_112", "WSASetLastError");
			ws2_32.put("ordinal_113", "WSACancelBlockingCall");
			ws2_32.put("ordinal_114", "WSAIsBlocking");
			ws2_32.put("ordinal_115", "WSAStartup");
			ws2_32.put("ordinal_116", "WSACleanup");
			ws2_32.put("ordinal_151", "__WSAFDIsSet");
			ws2_32.put("ordinal_500", "WEP");
		}

		static {
			maps = new HashMap<>();
			maps.put("oleaut32", oleaut32);
			maps.put("ws2_32", ws2_32);
		}


	}
	
	
}



	
