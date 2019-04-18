package com.obito.web;

import java.io.IOException;
import java.security.Provider;
import java.security.Security;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.common.messaging.context.SAMLEndpointContext;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.binding.decoding.impl.HTTPSOAP11Decoder;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPRedirectDeflateEncoder;
import org.opensaml.saml.saml2.core.AuthnContext;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml.saml2.metadata.Endpoint;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.config.JavaCryptoValidationInitializer;
import org.opensaml.xmlsec.context.SecurityParametersContext;
import org.opensaml.xmlsec.signature.support.SignatureConstants;

import com.obito.credentials.SPCredentials;
import com.obito.metadata.IDPMetadata;
import com.obito.metadata.SPMetadata;
import com.obito.util.OpenSAMLUtils;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;


public class AccessFilter implements Filter {
	
	protected static final Log log=LogFactory.getLog(AccessFilter.class);

	public void init(FilterConfig fConfig) throws ServletException {
		 try {
			 JavaCryptoValidationInitializer javaCryptoValidationInitializer =
		                new JavaCryptoValidationInitializer();
	            //�������Ӧ����OpenSAML��ʼ��֮ǰ�����ã�
	            //��ȷ����ǰ��JCE�������Է���Ҫ��AES/CBC/ISO10126Padding
	            // ����XML�ļ��ܣ�JCE��Ҫ֧��ACE��128/256������ʹ��ISO10126Padding�����λ��
	            javaCryptoValidationInitializer.init();
	        } catch (InitializationException e) {
	            e.printStackTrace();
	        }

	        //��ӡ��ǰ�Ѿ�����װ������JCE��provider
	        for (Provider jceProvider : Security.getProviders()) {
	            log.info(jceProvider.getInfo());
	        }

	        try {
	            log.info(" accessFilter Initializing");
	            InitializationService.initialize();
	        } catch (InitializationException e) {
	            throw new RuntimeException("Initialization failed");
	        }
	    }
	
	public void destroy() {
		
	}

	
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
		   HttpServletRequest httpServletRequest=(HttpServletRequest) request;
		   HttpServletResponse httpServletResponse=(HttpServletResponse) response;
		   //����Ѿ���֤�ˣ���ֱ���������
		   if(httpServletRequest.getSession().getAttribute(SPMetadata.AUTHENTICATED_SESSION_ATTRIBUTE)!=null) {
			   chain.doFilter(request, response);
		   }else {
			   //������η��ʵ�URL������֤���ض���
			   setLastAccessURL(httpServletRequest);
			   sendAuthRequestToIdp(httpServletResponse);
		   }
		
	}
   
	
	public void setLastAccessURL(HttpServletRequest request) {
		log.info("request url:"+request.getRequestURL());
     	request.getSession().setAttribute(SPMetadata.LAST_ACCESS_URL, request.getRequestURL());
	}
	
	public void sendAuthRequestToIdp(HttpServletResponse httpServletResponse) {
		 AuthnRequest authnRequest = buildAuthnRequest();
	     redirectUserWithRequest(httpServletResponse, authnRequest);	
	}
    
	 private void redirectUserWithRequest(HttpServletResponse httpServletResponse, AuthnRequest authnRequest) {
		   MessageContext context = new MessageContext();

	        context.setMessage(authnRequest);

	        //���ڴ���Զ�ʵ�����Ϣ������IDP����SP������SP����IDP��
	        SAMLPeerEntityContext peerEntityContext =
	                context.getSubcontext(SAMLPeerEntityContext.class, true);

	        //�˵���Ϣ��
	        SAMLEndpointContext endpointContext =
	                peerEntityContext.getSubcontext(SAMLEndpointContext.class, true);
	        endpointContext.setEndpoint(getIPDEndpoint());

	        //����ǩ������������
	        SignatureSigningParameters signatureSigningParameters = new SignatureSigningParameters();
	        //���֤�飬���а�����Կ
	        signatureSigningParameters.setSigningCredential(SPCredentials.getCredential());
	        //ALGO_ID_SIGNATURE_RSA_SHA256
	        signatureSigningParameters.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);


	        context.getSubcontext(SecurityParametersContext.class, true)
	                .setSignatureSigningParameters(signatureSigningParameters);

	        // OpenSAML�ṩ��HTTPRedirectDefalteEncoder
	        // ������������������AuthnRequest�������л���ǩ��
	        HTTPRedirectDeflateEncoder encoder = new HTTPRedirectDeflateEncoder();

	        encoder.setMessageContext(context);
	        encoder.setHttpServletResponse(httpServletResponse);

	        try {
	            encoder.initialize();
	        } catch (ComponentInitializationException e) {
	            throw new RuntimeException(e);
	        }

	        log.info("AuthnRequest: ");
	        OpenSAMLUtils.logSAMLObject(authnRequest);
	        log.info("Redirecting to IDP");
	        try {
	            //*encode*��������ѹ����Ϣ������ǩ������ӽ����URL���Ӷ����û���Idp.
	            //��ʹ��RFC1951��ΪĬ�Ϸ���ѹ�����ݣ��ڶ�ѹ�����������ϢBase64����
	            encoder.encode();
	        } catch (MessageEncodingException e) {
	            throw new RuntimeException(e);
	        }
		
	}

	private Endpoint getIPDEndpoint() {
		 SingleSignOnService endpoint = OpenSAMLUtils.buildSAMLObject(SingleSignOnService.class);
	     endpoint.setBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
	     endpoint.setLocation(getIDPSSOURL());
	     return endpoint;
	}

	private AuthnRequest buildAuthnRequest() {
	        AuthnRequest authnRequest = OpenSAMLUtils.buildSAMLObject(AuthnRequest.class);
	        //����ʱ�䣺�ö��󴴽���ʱ�䣬���ж���ʱЧ��
	        authnRequest.setIssueInstant(new DateTime());
	        //Ŀ��URL��Ŀ���ַ��IDP��ַ
	        authnRequest.setDestination(getIDPSSOURL());
	        //����SAML��������Ҫ�İ󶨣�Ҳ�����ú���Э��ʹ��Artifact��ȡ����������֤��Ϣ��
	        authnRequest.setProtocolBinding(SAMLConstants.SAML2_ARTIFACT_BINDING_URI);
	        //SP��ַ�� Ҳ����SAML���Է��صĵ�ַ
	        authnRequest.setAssertionConsumerServiceURL(getAssertionConsumerURL());
	        //�����ID��Ϊ��ǰ��������ID��һ��Ϊ�����
	        authnRequest.setID(OpenSAMLUtils.generateSecureRandomId());
	        //Issuer�� ��������Ϣ��Ҳ����SP��ID��һ����SP��URL
	        authnRequest.setIssuer(buildIssuer());
	        //NameID��IDP�����û���ݵı�ʶ��NameID policy��SP����NameID����δ�����˵��
	        authnRequest.setNameIDPolicy(buildNameIdPolicy());
	        // ������֤�����ģ�requested Authentication Context��:
	        // SP������֤��Ҫ�󣬰���SPϣ��IDP�����֤�û���Ҳ����IDPҪ����ʲô����֤�û���ݡ�
	        authnRequest.setRequestedAuthnContext(buildRequestedAuthnContext());

	        return authnRequest;
	    }

	private RequestedAuthnContext buildRequestedAuthnContext() {
		RequestedAuthnContext requestedAuthnContext = OpenSAMLUtils.buildSAMLObject(RequestedAuthnContext.class);
        requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.MINIMUM);

        AuthnContextClassRef passwordAuthnContextClassRef = OpenSAMLUtils.buildSAMLObject(AuthnContextClassRef.class);
        passwordAuthnContextClassRef.setAuthnContextClassRef(AuthnContext.PASSWORD_AUTHN_CTX);

        requestedAuthnContext.getAuthnContextClassRefs().add(passwordAuthnContextClassRef);

        return requestedAuthnContext;
	}

	private NameIDPolicy buildNameIdPolicy() {
		 NameIDPolicy nameIDPolicy = OpenSAMLUtils.buildSAMLObject(NameIDPolicy.class);
	     nameIDPolicy.setAllowCreate(true);
	     nameIDPolicy.setFormat(NameIDType.TRANSIENT);
	     return nameIDPolicy;
	}

	private Issuer buildIssuer() {
		Issuer issuer = OpenSAMLUtils.buildSAMLObject(Issuer.class);
        issuer.setValue(getSPIssuer());
        return issuer;
	}
	private String getSPIssuer() {
		return SPMetadata.SP_ENTITY_ID;
	}
	private String getAssertionConsumerURL() {
		// TODO Auto-generated method stub
		return SPMetadata.ASSERTION_CONSUMER_URL;
	}

	private String getIDPSSOURL() {
		return IDPMetadata.SSO_SERVICE;
	}


}
