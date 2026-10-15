// Analyzer hints, never reconstructed source or byte-gate admission.
// @category VC8
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.framework.Application;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;

public class ExportEvidence extends GhidraScript {
    private final Queue<DecompInterface> decompilers = new ConcurrentLinkedQueue<>();
    private final ThreadLocal<DecompInterface> localDecompiler = new ThreadLocal<>();
    private String binaryHash;
    private static final String HEADER = "va\trva\tname\tbody_bytes\trange_count\tboundary_provenance\tsignature_source\tunit\tunit_evidence\tdecompile_status\n";
    private static String safe(String value) { return value.replace("\t", " ").replace("\n", " ").replace("\r", " "); }
    private static String json(String value) {
        if (value == null) return "null";
        StringBuilder text = new StringBuilder("\"");
        for (char ch : value.toCharArray()) {
            if (ch == '\\' || ch == '"') text.append('\\').append(ch);
            else if (ch < 32) text.append(String.format("\\u%04x", (int)ch));
            else text.append(ch);
        }
        return text.append('"').toString();
    }
    private static BufferedWriter writer(Path path) throws IOException { return Files.newBufferedWriter(path, StandardCharsets.UTF_8); }
    private String row(Function function, String status) {
        Address entry = function.getEntryPoint();
        return entry + "\t0x" + Long.toHexString(entry.subtract(currentProgram.getImageBase())) + "\t" + safe(function.getName(true)) +
            "\t" + function.getBody().getNumAddresses() + "\t" + function.getBody().getNumAddressRanges() +
            "\tghidra_analysis_inferred\t" + function.getSignatureSource() + "\t\tunresolved\t" + status + "\n";
    }
    private static class Result {
        Function function;
        String status, error = "";
        boolean timedOut;
    }
    private Result decompile(Function function, Path out) throws Exception {
        Result result = new Result();
        result.function = function;
        String address = function.getEntryPoint().toString();
        try {
            DecompInterface decompiler = localDecompiler.get();
            if (decompiler == null) {
                decompiler = new DecompInterface();
                decompilers.add(decompiler);
                if (!decompiler.openProgram(currentProgram)) throw new IOException(decompiler.getLastMessage());
                localDecompiler.set(decompiler);
            }
            DecompileResults output = decompiler.decompileFunction(function, 60, monitor);
            result.timedOut = output.isTimedOut();
            if (output.decompileCompleted() && output.getDecompiledFunction() != null) {
                Files.writeString(out.resolve("functions").resolve(address + ".c"),
                    "/* GHIDRA HINT ONLY; boundary and signature inferred. */\n" + output.getDecompiledFunction().getC(), StandardCharsets.UTF_8);
                result.status = "complete";
            } else {
                result.status = "failed";
                result.error = output.getErrorMessage();
            }
        } catch (Exception exception) {
            result.status = "failed";
            result.error = exception.toString();
        }
        StringBuilder ranges = new StringBuilder("[");
        for (AddressRange range : function.getBody().getAddressRanges()) {
            if (ranges.length() > 1) ranges.append(',');
            ranges.append("{\"start_va\":").append(json(range.getMinAddress().toString()))
                .append(",\"end_va_inclusive\":").append(json(range.getMaxAddress().toString())).append('}');
        }
        ranges.append(']');
        Files.writeString(out.resolve("functions").resolve(address + ".json"),
            "{\"va\":" + json(address) + ",\"rva\":" + json("0x" + Long.toHexString(function.getEntryPoint().subtract(currentProgram.getImageBase()))) +
            ",\"name\":" + json(function.getName(true)) + ",\"binary_sha256\":" + json(binaryHash) +
            ",\"boundary_provenance\":\"ghidra_analysis_inferred\",\"ranges\":" + ranges +
            ",\"status\":" + json(result.status) + ",\"timed_out\":" + result.timedOut + ",\"error\":" + json(result.error) + "}\n",
            StandardCharsets.UTF_8);
        return result;
    }
    @Override protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2 || args.length > 3) throw new IllegalArgumentException("out dir, limit, optional workers 1..4 required");
        Path out = Paths.get(args[0]);
        int limit = Integer.parseInt(args[1]);
        int workers = args.length == 3 ? Integer.parseInt(args[2]) : 4;
        if (workers < 1 || workers > 4 || limit < 0) throw new IllegalArgumentException("workers must be 1..4; limit nonnegative");
        binaryHash = currentProgram.getExecutableSHA256();
        Files.createDirectories(out.resolve("functions"));
        List<Function> functions = new ArrayList<>();
        for (Function function : currentProgram.getFunctionManager().getFunctions(true)) functions.add(function);
        int selected = limit == 0 ? functions.size() : Math.min(limit, functions.size());
        // Complete metadata and assembly before any potentially slow decompilation.
        try (BufferedWriter table = writer(out.resolve("functions.tsv"));
             BufferedWriter ranges = writer(out.resolve("ranges.tsv"));
             BufferedWriter refs = writer(out.resolve("references.tsv"))) {
            table.write(HEADER);
            ranges.write("function_va\tstart_va\tend_va_inclusive\tprovenance\n");
            refs.write("function_va\tsite_va\ttarget_va\ttype\n");
            for (int index = 0; index < functions.size(); index++) {
                monitor.checkCancelled();
                Function function = functions.get(index);
                String address = function.getEntryPoint().toString();
                table.write(row(function, index < selected ? "pending" : "not_requested_limit"));
                for (AddressRange range : function.getBody().getAddressRanges())
                    ranges.write(address + "\t" + range.getMinAddress() + "\t" + range.getMaxAddress() + "\tghidra_analysis_inferred\n");
                AddressIterator sites = currentProgram.getReferenceManager().getReferenceSourceIterator(function.getBody(), true);
                while (sites.hasNext()) {
                    Address site = sites.next();
                    for (Reference reference : currentProgram.getReferenceManager().getReferencesFrom(site))
                        refs.write(address + "\t" + site + "\t" + reference.getToAddress() + "\t" + reference.getReferenceType() + "\n");
                }
                if (index < selected) {
                    try (BufferedWriter assembly = writer(out.resolve("functions").resolve(address + ".asm"))) {
                        InstructionIterator instructions = currentProgram.getListing().getInstructions(function.getBody(), true);
                        while (instructions.hasNext()) {
                            Instruction instruction = instructions.next();
                            assembly.write(instruction.getAddress() + "\t" + instruction + "\n");
                        }
                    }
                }
            }
        }
        Files.writeString(out.resolve("metadata-complete.json"), "{\"functions\":" + functions.size() + ",\"binary_sha256\":" + json(binaryHash) + "}\n");
        Map<String,String> statuses = new HashMap<>();
        int decompiled = 0, failed = 0, timedOut = 0;
        ExecutorService pool = Executors.newFixedThreadPool(workers);
        CompletionService<Result> completion = new ExecutorCompletionService<>(pool);
        try (BufferedWriter statusLog = writer(out.resolve("decompile-status.tsv"))) {
            statusLog.write("va\tname\tstatus\ttimed_out\terror\n");
            int submitted = 0;
            for (; submitted < Math.min(workers, selected); submitted++) {
                Function function = functions.get(submitted);
                completion.submit(() -> decompile(function, out));
            }
            for (int completed = 0; completed < selected; completed++) {
                monitor.checkCancelled();
                Result result = completion.take().get();
                String address = result.function.getEntryPoint().toString();
                statuses.put(address, result.status);
                if (result.status.equals("complete")) decompiled++; else failed++;
                if (result.timedOut) timedOut++;
                statusLog.write(address + "\t" + safe(result.function.getName(true)) + "\t" + result.status + "\t" + result.timedOut + "\t" + safe(result.error == null ? "" : result.error) + "\n");
                statusLog.flush();
                if (submitted < selected) {
                    Function function = functions.get(submitted++);
                    completion.submit(() -> decompile(function, out));
                }
            }
        } finally {
            pool.shutdownNow();
            pool.awaitTermination(30, TimeUnit.SECONDS);
            for (DecompInterface decompiler : decompilers) decompiler.dispose();
        }
        try (BufferedWriter table = writer(out.resolve("functions.tsv.tmp"))) {
            table.write(HEADER);
            for (Function function : functions) table.write(row(function, statuses.getOrDefault(function.getEntryPoint().toString(), "not_requested_limit")));
        }
        Files.move(out.resolve("functions.tsv.tmp"), out.resolve("functions.tsv"), StandardCopyOption.REPLACE_EXISTING);
        Files.writeString(out.resolve("export-complete.json"), "{\"ghidra_version\":\"" + Application.getApplicationVersion() +
            "\",\"binary_sha256\":" + json(binaryHash) + ",\"functions\":" + functions.size() + ",\"decompiled\":" + decompiled +
            ",\"failed\":" + failed + ",\"timed_out\":" + timedOut + ",\"workers\":" + workers + "}\n");
        println("VC8 EXPORT: functions=" + functions.size() + " decompiled=" + decompiled + " failed=" + failed + " timed_out=" + timedOut + " workers=" + workers);
    }
}
