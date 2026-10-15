// Local validated PDB application; disables automatic symbol-server searches.
// @category VC8
import java.io.File;
import java.nio.file.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.format.pdb2.pdbreader.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.pdb.pdbapplicator.*;

public class PrepareEvidence extends GhidraScript {
    @Override protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) throw new IllegalArgumentException("PDB path or -, status path required");
        setAnalysisOption(currentProgram, "PDB Universal", "false");
        setAnalysisOption(currentProgram, "PDB", "false");
        String status = "not_requested";
        if (!args[0].equals("-")) {
            MessageLog log = new MessageLog();
            try (AbstractPdb pdb = PdbParser.parse(new File(args[0]), new PdbReaderOptions(), monitor)) {
                pdb.deserialize();
                DefaultPdbApplicator applicator = new DefaultPdbApplicator(pdb, currentProgram,
                    currentProgram.getDataTypeManager(), currentProgram.getImageBase(),
                    new PdbApplicatorOptions(), monitor, log);
                applicator.applyNoAnalysisState();
                status = "applied_local_validated_pdb";
            }
            Files.writeString(Paths.get(args[1] + ".log"), log.toString());
        }
        Files.writeString(Paths.get(args[1]), "{\"status\":\"" + status + "\",\"remote_search\":false}\n");
        println("VC8 PDB: " + status);
    }
}
