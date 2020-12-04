package com.example.sdk;

import com.synopsys.defensics.api.io.TcpInjector;
import com.synopsys.defensics.api.message.ElementFactory;
import com.synopsys.defensics.api.run.FuzzerBuilder;
import com.synopsys.defensics.sdk.BuilderTools;
import com.synopsys.defensics.api.message.*;

public class BitcoinSuite implements FuzzerBuilder {

  /**
   * Command-line argument for HOST setting.
   */
  public static final String ARG_HOST =
      "--target-host";

  /**
   * Label for HOST setting.
   */
  public static final String LABEL_HOST =
      "Target host";

  /**
   * Help text for HOST setting.
   */
  public static final String HELP_HOST =
      "The hostname or ip address of the test target.";

  /**
   * Command-line argument for TARGET_PORT setting.
   */
  public static final String ARG_TARGET_PORT =
      "--target-port";

  /**
   * Label for TARGET_PORT setting.
   */
  public static final String LABEL_TARGET_PORT =
      "Target port";

  /**
   * Help text for TARGET_PORT setting.
   */
  public static final String HELP_TARGET_PORT =
      "The target port where the test cases are sent to.";

  /**
   * Command-line argument for SOURCE_PORT setting.
   */
  public static final String ARG_SOURCE_PORT =
      "--source-port";

  /**
   * Label for SOURCE_PORT setting.
   */
  public static final String LABEL_SOURCE_PORT =
      "Source port";

  /**
   * Help text for SOURCE_PORT setting.
   */
  public static final String HELP_SOURCE_PORT =
      "The source port where the test cases are sent from. Use -1 for dynamic source port.";

  /**
   * Command-line argument for SEQUENCE setting.
   */
  public static final String ARG_SEQUENCE =
      "--sequence";

  /**
   * Label for SEQUENCE setting.
   */
  public static final String LABEL_SEQUENCE =
      "Sequence file";

  /**
   * Help text for SEQUENCE setting.
   */
  public static final String HELP_SEQUENCE =
      "Edit sequence or choose another sequence file";

  @Override
  public void build(BuilderTools tools) throws Exception {
    ElementFactory factory = tools.factory();

    // Set up rules
    RuleFactory rf = tools.rule();
    rf.correlate("corr");
    rf.length("length32").format("int-lsb-32bit");
    rf.checksum("sha256x2", new SHA256x2());
    
    factory.readTypes(tools.resources().getPathToResource("model.bnf"));

    // Create messages
    MessageElement version = tools.factory().getType("bitcoin-message");
    version.find().mandatory("version-name").element().select();
    tools.messages().message("version", version).finish();
    
    MessageElement verack = tools.factory().getType("bitcoin-message");
    verack.find().mandatory("verack-name").element().select();
    tools.messages().message("verack", verack).finish();
    
    // Disable anomalies for the alternative choice payload types
    tools.testCaseConfig().disableAlternativeChoiceAnomalies(
        "version-payload", 
        "verack-payload", 
        "any-payload");

    // Create io
    String host = getHost(tools);
    int port = getPort(tools);
    int sourcePort = getSourcePort(tools);
    TcpInjector io = tools.injector().tcp()
        .host(host)
        .port(port)
        .localPort(sourcePort);

    tools.buildSequence(io)
        .createSequencesFrom(tools.resources().getPathToResource(getSequence(tools)));
  }

  /**
   * Read host setting value.
   *
   * @param tools the builder tools for setting value reading.
   * @return the value for host setting.
   */
  private String getHost(BuilderTools tools) {
    String host = tools.settings().addSetting(
        ARG_HOST,
        "172.17.0.3",
        LABEL_HOST)
        .setDocumentation(HELP_HOST)
        .getValue();
    return host;
  }

  /**
   * Read target port setting value.
   *
   * @param tools the builder tools for setting value reading.
   * @return the value for target port setting.
   * @throws NumberFormatException if setting value conversion to int fails.
   */
  private int getPort(BuilderTools tools) {
    String port = tools.settings().addSetting(
        ARG_TARGET_PORT,
        "18444",
        LABEL_TARGET_PORT)
        .setDocumentation(HELP_TARGET_PORT)
        .getValue();
    int result = Integer.parseInt(port);
    return result;
  }

  /**
   * Read source port setting value.
   *
   * @param tools the builder tools for setting value reading.
   * @return the value for source port setting.
   * @throws NumberFormatException if setting value conversion to int fails.
   */
  private int getSourcePort(BuilderTools tools) {
    String sourcePort = tools.settings().addSetting(
        ARG_SOURCE_PORT,
        "-1",
        LABEL_SOURCE_PORT)
        .setDocumentation(HELP_SOURCE_PORT)
        .getValue();
    int result = Integer.parseInt(sourcePort);
    return result;
  }

  /**
   * Read sequence setting value.
   *
   * @param tools the builder tools for setting value reading.
   * @return the value for sequence setting.
   */
  private String getSequence(BuilderTools tools) {
    String sequence = tools.settings().addSequenceFileSetting(
        ARG_SEQUENCE,
        "sequence.seq",
        LABEL_SEQUENCE)
        .setDocumentation(HELP_SEQUENCE)
        .getValue();
    return sequence;
  }

}
