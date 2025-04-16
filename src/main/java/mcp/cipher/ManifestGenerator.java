package mcp.cipher;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.classgraph.ClassGraph;
import io.github.classgraph.ClassInfo;
import io.github.classgraph.ScanResult;
import org.springframework.ai.tool.annotation.Tool;

import java.io.File;
import java.lang.reflect.Method;
import java.lang.reflect.Parameter;

public class ManifestGenerator {
    private static final String TOOL_NAME = "MCP-Cipher";
    private static final String VERSION = "0.0.1";

    public static void main(String[] args) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode manifest = mapper.createObjectNode();

        manifest.put("tool_name", TOOL_NAME);
        manifest.put("version", VERSION);
        manifest.put("description", "A Java-based MCP-compatible tool that provides encryption, decryption, hashing, HMAC, and key generation functionalities using AES, RSA, SHA-256, and more.");

        ObjectNode entrypoint = manifest.putObject("entrypoint");
        entrypoint.put("command", "java");

        ArrayNode argsArray = entrypoint.putArray("args");
        argsArray.add("-jar");
        argsArray.add("./libs/" + TOOL_NAME + "-" + VERSION + "-SNAPSHOT.jar");

        ArrayNode actions = manifest.putArray("actions");

        try (ScanResult scanResult = new ClassGraph()
                .acceptPackages("mcp.cipher.tool")
                .enableClassInfo()
                .enableAnnotationInfo()
                .scan()) {

            for (ClassInfo classInfo : scanResult.getAllClasses()) {
                Class<?> clazz = classInfo.loadClass();

                for (Method method : clazz.getDeclaredMethods()) {
                    if (!method.isAnnotationPresent(Tool.class)) {
                        continue;
                    }

                    Tool tool = method.getAnnotation(Tool.class);

                    ObjectNode action = mapper.createObjectNode();
                    action.put("name", method.getName());
                    action.put("description", tool.description());

                    ObjectNode params = mapper.createObjectNode();

                    for (Parameter param : method.getParameters()) {
                        params.put(param.getName(), mapType(param.getType()));
                    }

                    action.set("parameters", params);
                    actions.add(action);
                }
            }
        }

        mapper.writerWithDefaultPrettyPrinter()
                .writeValue(new File("manifest.json"), manifest);

        System.out.println("-> manifest.json generated successfully!");
    }

    private static String mapType(Class<?> type) {
        if (Number.class.isAssignableFrom(type) || type.isPrimitive()) {
            return "number";
        }

        if (type == String.class) {
            return "string";
        }

        if (type == Boolean.class || type == boolean.class) {
            return "boolean";
        }

        return "any";
    }
}
