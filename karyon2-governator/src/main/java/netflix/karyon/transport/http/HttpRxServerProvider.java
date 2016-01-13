package netflix.karyon.transport.http;

import static netflix.karyon.utils.TypeUtils.keyFor;
import io.netty.buffer.ByteBufAllocator;
import io.netty.handler.ssl.ApplicationProtocolConfig;
import io.netty.handler.ssl.CipherSuiteFilter;
import io.netty.handler.ssl.IdentityCipherSuiteFilter;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslProvider;
import io.netty.handler.ssl.util.SelfSignedCertificate;
import io.reactivex.netty.metrics.MetricEventsListenerFactory;
import io.reactivex.netty.pipeline.PipelineConfigurator;
import io.reactivex.netty.pipeline.ssl.SSLEngineFactory;
import io.reactivex.netty.protocol.http.server.HttpServer;
import io.reactivex.netty.protocol.http.server.HttpServerBuilder;
import io.reactivex.netty.protocol.http.server.RequestHandler;

import java.io.File;
import java.security.cert.CertificateException;

import javax.annotation.PreDestroy;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;

import netflix.karyon.transport.AbstractServerModule.ServerConfig;
import netflix.karyon.transport.KaryonTransport;
import netflix.karyon.transport.http.KaryonHttpModule.HttpServerConfig;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.Inject;
import com.google.inject.Injector;
import com.google.inject.Key;
import com.google.inject.Provider;
import com.google.inject.name.Named;
import com.google.inject.name.Names;

/**
 * @author Tomasz Bak
 */
@SuppressWarnings("unchecked")
public class HttpRxServerProvider<I, O, S extends HttpServer<I, O>> implements Provider<S> {

    private static final Logger logger = LoggerFactory.getLogger(HttpRxServerProvider.class);

    private final Named nameAnnotation;
    private final Key<RequestHandler<I, O>> routerKey;
    private final Key<GovernatorHttpInterceptorSupport<I, O>> interceptorSupportKey;
    @SuppressWarnings("rawtypes")
    private final Key<PipelineConfigurator> pipelineConfiguratorKey;
    private final Key<MetricEventsListenerFactory> metricEventsListenerFactoryKey;
    private final Key<ServerConfig> serverConfigKey;

    private volatile HttpServer<I, O> httpServer;
    private volatile HttpServer<I, O> httpsServer;

    public HttpRxServerProvider(String name, Class<I> iType, Class<O> oType) {
        nameAnnotation = Names.named(name);

        routerKey = keyFor(RequestHandler.class, iType, oType, nameAnnotation);
        interceptorSupportKey = keyFor(GovernatorHttpInterceptorSupport.class, iType, oType, nameAnnotation);
        pipelineConfiguratorKey = Key.get(PipelineConfigurator.class, nameAnnotation);
        metricEventsListenerFactoryKey = Key.get(MetricEventsListenerFactory.class, nameAnnotation);
        serverConfigKey = Key.get(ServerConfig.class, nameAnnotation);
    }

    @Override
    public S get() {
        return (S) httpServer;
    }

    @PreDestroy
    public void shutdown() throws InterruptedException {
        if (httpServer != null) {
            httpServer.shutdown();
        }
        if (httpsServer != null) {
            httpsServer.shutdown();
        }
    }

    @SuppressWarnings("rawtypes")
    @Inject
    public void setInjector(Injector injector) {
        boolean enableSSL = Boolean.parseBoolean(System.getProperty("karyon.ssl", "false"));
        int sslPort = Integer.parseInt(System.getProperty("karyon.ssl.port", "8443"));
        
        HttpServerConfig config = (HttpServerConfig) injector.getInstance(serverConfigKey);

        RequestHandler router = injector.getInstance(routerKey);

        GovernatorHttpInterceptorSupport<I, O> interceptorSupport = injector.getInstance(interceptorSupportKey);
        interceptorSupport.finish(injector);
        HttpRequestHandler<I, O> httpRequestHandler = new HttpRequestHandler<I, O>(router, interceptorSupport);

        HttpServerBuilder<I, O> builder = KaryonTransport.newHttpServerBuilder(config.getPort(), httpRequestHandler);
        HttpServerBuilder<I, O> sslBuilder = KaryonTransport.newHttpServerBuilder(sslPort, httpRequestHandler);

        if (config.requiresThreadPool()) {
            builder.withRequestProcessingThreads(config.getThreadPoolSize());
            sslBuilder.withRequestProcessingThreads(config.getThreadPoolSize());
        }

        if (injector.getExistingBinding(pipelineConfiguratorKey) != null) {
            builder.appendPipelineConfigurator(injector.getInstance(pipelineConfiguratorKey));
            sslBuilder.appendPipelineConfigurator(injector.getInstance(pipelineConfiguratorKey));
        }

        if (injector.getExistingBinding(metricEventsListenerFactoryKey) != null) {
            builder.withMetricEventsListenerFactory(injector.getInstance(metricEventsListenerFactoryKey));
            sslBuilder.withMetricEventsListenerFactory(injector.getInstance(metricEventsListenerFactoryKey));
        }
        httpServer = builder.build().start();
        logger.info("Starting Rx HTTP Server {} on port {}...", nameAnnotation.value(), httpServer.getServerPort());     

        if (enableSSL) {
            sslBuilder.withSslEngineFactory(new CustomSSLEngineFactory());
            httpsServer = sslBuilder.build().start();
            logger.info("Starting Rx HTTPS Server {} on port {}...", nameAnnotation.value(), httpsServer.getServerPort());
        }
    }
    
    private static class CustomSSLEngineFactory implements SSLEngineFactory {

        private final SslContext sslCtx;
        private static String certPath = System.getProperty("karyon.ssl.certificate", null);
        private static String privateKeyPath = System.getProperty("karyon.ssl.privatekey", null);
        private static String cipherSuitesList = System.getProperty("karyon.ssl.ciphersuites",null);
        private static int sessionSize = Integer.parseInt(System.getProperty("karyon.ssl.session.size","1000")); 
        private static int sessionTimeout = Integer.parseInt(System.getProperty("karyon.ssl.session.timeout","300")); //5 minutes
        private CustomSSLEngineFactory() {
            if (certPath == null || privateKeyPath == null)
                generateSelfSignedCert();
            if (cipherSuitesList != null && cipherSuitesList.equals("default"))
                cipherSuitesList = "SSL_RSA_WITH_AES_128_CBC_SHA256,SSL_RSA_WITH_AES_128_CBC_SHA,SSL_RSA_WITH_AES_256_CBC_SHA256,SSL_RSA_WITH_AES_256_CBC_SHA";
            logger.info("Setting up SSL Context using the certificate [" + certPath + "], private key ["
                    + privateKeyPath + "], Session Size ["+sessionSize+"], Session timeout ["+sessionTimeout+"]");
            try {
                sslCtx = SslContext.newServerContext(null,new File(certPath), new File(privateKeyPath)
                      ,null,null, IdentityCipherSuiteFilter.INSTANCE,null,sessionSize,sessionTimeout);
            } catch (SSLException e) {
                throw new IllegalStateException("Failed to create Netty's Ssl context with the specified certificate",
                        e);
            }
        }

        private void generateSelfSignedCert() {
            logger.info("No external certificate or private key provided. Trying to generate a self signed certificate.");
            SelfSignedCertificate ssc;
            try {
                ssc = new SelfSignedCertificate();
            } catch (CertificateException e) {
                throw new IllegalStateException("Self signed certificate creation error", e);
            }
            certPath = ssc.certificate().getAbsolutePath();
            privateKeyPath = ssc.privateKey().getAbsolutePath();
        }

        @Override
        public SSLEngine createSSLEngine(ByteBufAllocator allocator) {
            SSLEngine sslEngine =  sslCtx.newEngine(allocator);
            sslEngine.setEnabledProtocols(new String[] { "TLS" });
            if (cipherSuitesList != null) {
                String cipherSuiteArray[] = cipherSuitesList.split(",");
                sslEngine.setEnabledCipherSuites(cipherSuiteArray);
            }
            return sslEngine;
        }
    }
}
