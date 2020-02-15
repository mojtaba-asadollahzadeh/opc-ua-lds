import org.eclipse.milo.opcua.sdk.server.OpcUaServer;
import org.eclipse.milo.opcua.sdk.server.api.config.OpcUaServerConfig;
import org.eclipse.milo.opcua.sdk.server.identity.CompositeValidator;
import org.eclipse.milo.opcua.sdk.server.identity.UsernameIdentityValidator;
import org.eclipse.milo.opcua.sdk.server.identity.X509IdentityValidator;
import org.eclipse.milo.opcua.sdk.server.util.HostnameUtil;
import org.eclipse.milo.opcua.stack.core.StatusCodes;
import org.eclipse.milo.opcua.stack.core.UaRuntimeException;
import org.eclipse.milo.opcua.stack.core.security.DefaultCertificateManager;
import org.eclipse.milo.opcua.stack.core.security.DefaultCertificateValidator;
import org.eclipse.milo.opcua.stack.core.security.DefaultTrustListManager;
import org.eclipse.milo.opcua.stack.core.security.SecurityPolicy;
import org.eclipse.milo.opcua.stack.core.transport.TransportProfile;
import org.eclipse.milo.opcua.stack.core.types.builtin.DateTime;
import org.eclipse.milo.opcua.stack.core.types.builtin.LocalizedText;
import org.eclipse.milo.opcua.stack.core.types.enumerated.MessageSecurityMode;
import org.eclipse.milo.opcua.stack.core.types.structured.BuildInfo;
import org.eclipse.milo.opcua.stack.server.EndpointConfiguration;

import java.io.File;
import java.security.cert.X509Certificate;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

import static com.google.common.collect.Lists.newArrayList;
import static org.eclipse.milo.opcua.sdk.server.api.config.OpcUaServerConfig.USER_TOKEN_POLICY_ANONYMOUS;

public class ExampleLds {

	private static final int TCP_PORT = 4840;
	private static final int HTTPS_PORT = 8443;



	private final OpcUaServer server;


	public static void main(String[] args) throws Exception {
		ExampleLds server = new ExampleLds();

		server.startup().get();

		final CompletableFuture<Void> future = new CompletableFuture<>();

		Runtime.getRuntime().addShutdownHook(new Thread(() -> future.complete(null)));

		future.get();

	}

	public ExampleLds() throws Exception {

		String server_name = "fanitoring-lds";

		File securityTempDir = new File(System.getProperty("java.io.tmpdir"), "lds-security");
		if (!securityTempDir.exists() && !securityTempDir.mkdirs()) {
			throw new Exception("unable to create security temp dir: " + securityTempDir);
		}

		File pkiDir = securityTempDir.toPath().resolve("pki").toFile();
		DefaultTrustListManager trustListManager = new DefaultTrustListManager(pkiDir);

		DefaultCertificateValidator certificateValidator = new DefaultCertificateValidator(trustListManager);

		UsernameIdentityValidator identityValidator = new UsernameIdentityValidator(
				true,
				authChallenge -> {
					return true;
				}
		);



		List<String> bindAddresses = newArrayList();
		bindAddresses.add("0.0.0.0");

		KeyStoreLoader loader = new KeyStoreLoader().load(securityTempDir);

		DefaultCertificateManager certificateManager = new DefaultCertificateManager(
				loader.getServerKeyPair(),
				loader.getServerCertificateChain()
		);

		X509IdentityValidator x509IdentityValidator = new X509IdentityValidator(c -> true);
		X509Certificate certificate = certificateManager.getCertificates()
				.stream()
				.findFirst()
				.orElseThrow(() -> new UaRuntimeException(StatusCodes.Bad_ConfigurationError, "no certificate found"));

		Set<EndpointConfiguration> endpointConfigurations = createEndpointConfigurations(certificate);

		OpcUaServerConfig serverConfig = OpcUaServerConfig.builder()
				.setApplicationUri("urn:fanitoring:lds:server")
				.setApplicationName(LocalizedText.english("Fanitoring Local Discovery Server"))
				.setEndpoints(endpointConfigurations)
				.setBuildInfo(
						new BuildInfo(
								"urn:fanitoring:lds:server",
								"fanitoring",
								"Fanitoring Local Discovery Server",
								OpcUaServer.SDK_VERSION,
								"v.0.1", DateTime.now()))
				.setCertificateManager(certificateManager)
				.setCertificateValidator(certificateValidator)
				.setIdentityValidator(new CompositeValidator(identityValidator,x509IdentityValidator))
				.setProductUri("urn:fanitoring:lds:server")
				.build();

		server = new OpcUaServer(serverConfig,true);

	}

	private static Set<EndpointConfiguration> createEndpointConfigurations(X509Certificate certificate) {
		Set<EndpointConfiguration> endpointConfigurations = new LinkedHashSet<>();

		List<String> bindAddresses = newArrayList();
		bindAddresses.add("0.0.0.0");

		Set<String> hostnames = new LinkedHashSet<>();
		hostnames.add(HostnameUtil.getHostname());
		hostnames.addAll(HostnameUtil.getHostnames("0.0.0.0"));


		for (String bindAddress : bindAddresses) {
			for (String hostname : hostnames) {
				EndpointConfiguration.Builder builder = EndpointConfiguration.newBuilder()
						.setBindAddress(bindAddress)
						.setHostname(hostname)
						.setPath("/lds")
						.addTokenPolicies(USER_TOKEN_POLICY_ANONYMOUS);


				EndpointConfiguration.Builder noSecurityBuilder = builder.copy()
						.setSecurityPolicy(SecurityPolicy.None)
						.setSecurityMode(MessageSecurityMode.None);

				endpointConfigurations.add(buildTcpEndpoint(noSecurityBuilder));
				endpointConfigurations.add(buildHttpsEndpoint(noSecurityBuilder));

				EndpointConfiguration.Builder discoveryBuilder = builder.copy()
						.setPath("/discovery")
						.setSecurityPolicy(SecurityPolicy.None)
						.setSecurityMode(MessageSecurityMode.None);

				endpointConfigurations.add(buildTcpEndpoint(discoveryBuilder));
				endpointConfigurations.add(buildHttpsEndpoint(discoveryBuilder));

			}
		}

		return endpointConfigurations;
	}

	private static EndpointConfiguration buildTcpEndpoint(EndpointConfiguration.Builder base) {
		return base.copy()
				.setTransportProfile(TransportProfile.TCP_UASC_UABINARY)
				.setBindPort(TCP_PORT)
				.build();
	}

	private static EndpointConfiguration buildHttpsEndpoint(EndpointConfiguration.Builder base) {
		return base.copy()
				.setTransportProfile(TransportProfile.HTTPS_UABINARY)
				.setBindPort(HTTPS_PORT)
				.build();
	}



	public OpcUaServer getServer() {
		return server;
	}

	public CompletableFuture<OpcUaServer> startup() {
		return server.startup();
	}

}