// Analyzer hints, never reconstructed source or byte-gate admission.
// @category VC8
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.framework.Application;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;

public class ExportEvidence extends GhidraScript {
    private static String safe(String value) { return value.replace("\t", " ").replace("\n", " ").replace("\r", " "); }
    private static BufferedWriter writer(Path path) throws IOException { return Files.newBufferedWriter(path, StandardCharsets.UTF_8); }
    @Override protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) throw new IllegalArgumentException("out dir and limit required");
        Path out = Paths.get(args[0]);
        int limit = Integer.parseInt(args[1]), count = 0, decompiled = 0, failed = 0;
        Files.createDirectories(out.resolve("functions"));
        DecompInterface decompiler = new DecompInterface();
        if (!decompiler.openProgram(currentProgram)) throw new IOException(decompiler.getLastMessage());
        try (BufferedWriter table = writer(out.resolve("functions.tsv"));
             BufferedWriter ranges = writer(out.resolve("ranges.tsv"));
             BufferedWriter refs = writer(out.resolve("references.tsv"))) {
            table.write("va\trva\tname\tbody_bytes\trange_count\tboundary_provenance\tsignature_source\tunit\tunit_evidence\tdecompile_status\n");
            ranges.write("function_va\tstart_va\tend_va_inclusive\tprovenance\n");
            refs.write("function_va\tsite_va\ttarget_va\ttype\n");
            for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
                monitor.checkCancelled();
                Address entry = function.getEntryPoint();
                String address = entry.toString();
                String status = "not_requested_limit";
                if (limit == 0 || count < limit) {
                    DecompileResults result = decompiler.decompileFunction(function, 60, monitor);
                    if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
                        Files.writeString(out.resolve("functions").resolve(address + ".c"),
                            "/* GHIDRA HINT ONLY; boundary and signature inferred. */\n" + result.getDecompiledFunction().getC(), StandardCharsets.UTF_8);
                        status = "complete"; decompiled++;
                    } else { status = "failed"; failed++; }
                    try (BufferedWriter assembly = writer(out.resolve("functions").resolve(address + ".asm"))) {
                        InstructionIterator instructions = currentProgram.getListing().getInstructions(function.getBody(), true);
                        while (instructions.hasNext()) {
                            Instruction instruction = instructions.next();
                            assembly.write(instruction.getAddress() + "\t" + instruction + "\n");
                        }
                    }
                }
                table.write(address + "\t0x" + Long.toHexString(entry.subtract(currentProgram.getImageBase())) + "\t" + safe(function.getName(true)) +
                    "\t" + function.getBody().getNumAddresses() + "\t" + function.getBody().getNumAddressRanges() +
                    "\tghidra_analysis_inferred\t" + function.getSignatureSource() + "\t\tunresolved\t" + status + "\n");
                for (AddressRange range : function.getBody().getAddressRanges())
                    ranges.write(address + "\t" + range.getMinAddress() + "\t" + range.getMaxAddress() + "\tghidra_analysis_inferred\n");
                AddressIterator sites = currentProgram.getReferenceManager().getReferenceSourceIterator(function.getBody(), true);
                while (sites.hasNext()) {
                    Address site = sites.next();
                    for (Reference reference : currentProgram.getReferenceManager().getReferencesFrom(site))
                        refs.write(address + "\t" + site + "\t" + reference.getToAddress() + "\t" + reference.getReferenceType() + "\n");
                }
                count++;
            }
        } finally { decompiler.dispose(); }
        Files.writeString(out.resolve("export-complete.json"), "{\"ghidra_version\":\"" + Application.getApplicationVersion() +
            "\",\"functions\":" + count + ",\"decompiled\":" + decompiled + ",\"failed\":" + failed + "}\n");
        println("VC8 EXPORT: functions=" + count + " decompiled=" + decompiled + " failed=" + failed);
    }
}
