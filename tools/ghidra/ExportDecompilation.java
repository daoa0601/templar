// Templar-owned Ghidra headless post-script. It statically decompiles; it never executes a target.
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public final class ExportDecompilation extends GhidraScript {
  private long writtenBytes;
  private long maximumBytes;

  private void write(BufferedWriter writer, String value) throws IOException {
    long encodedBytes = value.getBytes(StandardCharsets.UTF_8).length;
    if (writtenBytes + encodedBytes > maximumBytes) {
      throw new IOException("Templar Ghidra decompilation exceeds its output limit");
    }
    writer.write(value);
    writtenBytes += encodedBytes;
  }

  @Override
  protected void run() throws Exception {
    String[] arguments = getScriptArgs();
    if (arguments.length != 2) {
      throw new IllegalArgumentException("Usage: ExportDecompilation.java <output-path> <max-bytes>");
    }
    maximumBytes = Long.parseLong(arguments[1]);
    if (maximumBytes <= 0 || maximumBytes > 32L * 1024L * 1024L) {
      throw new IllegalArgumentException("max-bytes must be between 1 and 33554432");
    }

    Path output = Path.of(arguments[0]).toAbsolutePath().normalize();
    DecompInterface decompiler = new DecompInterface();
    decompiler.toggleCCode(true);
    decompiler.toggleSyntaxTree(true);
    if (!decompiler.openProgram(currentProgram)) {
      throw new IOException("Ghidra could not initialize its decompiler");
    }

    int functionCount = 0;
    try (BufferedWriter writer = Files.newBufferedWriter(output, StandardCharsets.UTF_8)) {
      write(writer, "PROGRAM " + currentProgram.getName() + "\n");
      write(writer, "LANGUAGE " + currentProgram.getLanguageID() + "\n\n");
      for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
        monitor.checkCancelled();
        functionCount += 1;
        if (functionCount > 4096) {
          throw new IOException("Templar Ghidra function limit exceeded");
        }
        write(
            writer,
            "=== FUNCTION "
                + function.getEntryPoint()
                + " "
                + function.getName(true)
                + " ===\n");
        write(writer, function.getPrototypeString(true, false) + "\n");
        DecompileResults results = decompiler.decompileFunction(function, 60, monitor);
        if (results.decompileCompleted() && results.getDecompiledFunction() != null) {
          write(writer, results.getDecompiledFunction().getC());
        } else {
          write(writer, "/* DECOMPILATION_FAILED: " + results.getErrorMessage() + " */\n");
        }
        write(writer, "\n");
      }
    } finally {
      decompiler.dispose();
    }
    println("Templar exported " + functionCount + " functions to " + output);
  }
}
