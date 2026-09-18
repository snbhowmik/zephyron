import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Stream;
import org.pqca.indexing.ProjectModule;
import org.pqca.indexing.java.JavaIndexService;
import org.pqca.indexing.python.PythonIndexService;
import org.pqca.scanning.CBOM;
import org.pqca.scanning.ScanResultDTO;
import org.pqca.scanning.java.JavaScannerService;
import org.pqca.scanning.python.PythonScannerService;

/**
 * QAVACH's entrypoint around cbomkit-lib (NOTE.md 3.2): index and scan /target for Java and Python,
 * merge the results and print one CycloneDX CBOM to stdout. Nothing else is written to stdout.
 *
 * <p>cbomkit-lib has no main of its own. Java scanning is source-only unless the target carries
 * jars or compiled classes; the sandbox has no network, so this never builds the target.
 */
public final class QavachScan {
    private QavachScan() {}

    public static void main(String[] args) throws Exception {
        final File root = new File(args.length > 0 ? args[0] : "/target").getAbsoluteFile();
        CBOM merged = null;

        final List<ProjectModule> javaModules = new JavaIndexService(root).index(null);
        if (!javaModules.isEmpty()) {
            final JavaScannerService java = new JavaScannerService(root);
            java.setRequireBuild(false);
            try (Stream<Path> walk = Files.walk(root.toPath())) {
                walk.filter(p -> p.toString().endsWith(".jar"))
                        .forEach(p -> java.addJavaDependencyJar(p.toString()));
            }
            merged = merge(merged, java.scan(javaModules));
        }

        final List<ProjectModule> pythonModules = new PythonIndexService(root).index(null);
        if (!pythonModules.isEmpty()) {
            merged = merge(merged, new PythonScannerService(root).scan(pythonModules));
        }

        if (merged == null) {
            System.out.println("{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.6\",\"components\":[]}");
            return;
        }
        System.out.println(merged.toJSON().toString());
    }

    private static CBOM merge(CBOM into, ScanResultDTO result) {
        if (result.cbom() == null) {
            return into;
        }
        if (into == null) {
            return result.cbom();
        }
        into.merge(result.cbom());
        return into;
    }
}
