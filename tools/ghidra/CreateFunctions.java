// PDB publics prove starts only. Record analyzer boundaries without promoting them to exact bodies.
// @category VC8
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;

public class CreateFunctions extends GhidraScript {
    @Override protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) throw new IllegalArgumentException("start TSV and audit TSV required");
        int created = 0, conflict = 0, existing = 0, failed = 0;
        try (BufferedReader in = Files.newBufferedReader(Paths.get(args[0]), StandardCharsets.UTF_8);
             BufferedWriter out = Files.newBufferedWriter(Paths.get(args[1]), StandardCharsets.UTF_8)) {
            out.write("va\tpublic_name\tstatus\tcontaining_entry\tboundary_provenance\n");
            String line;
            while ((line = in.readLine()) != null) {
                monitor.checkCancelled();
                String[] fields = line.split("\t", 2);
                Address address = toAddr(Long.parseUnsignedLong(fields[0], 16));
                String status;
                Function function = getFunctionContaining(address);
                if (function != null) {
                    if (function.getEntryPoint().equals(address)) { status = "existing"; existing++; }
                    else { status = "inside_existing_function_conflict"; conflict++; }
                } else {
                    MemoryBlock block = currentProgram.getMemory().getBlock(address);
                    if (block == null || !block.isExecute()) { status = "not_executable"; failed++; }
                    else {
                        if (getInstructionAt(address) == null) disassemble(address);
                        function = createFunction(address, null);
                        if (function == null) { status = "creation_failed"; failed++; }
                        else { status = "created"; created++; }
                    }
                }
                out.write(fields[0] + "\t" + (fields.length > 1 ? fields[1] : "") + "\t" + status + "\t" +
                    (function == null ? "" : function.getEntryPoint().toString()) +
                    "\tpdb_public_start;ghidra_body_inferred\n");
            }
        }
        println("VC8 CREATE: created=" + created + " existing=" + existing + " conflicts=" + conflict + " failed=" + failed);
    }
}
