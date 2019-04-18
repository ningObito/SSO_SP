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
	            //这个方法应该在OpenSAML初始化之前被调用，
	            //来确保当前的JCE环境可以符合要求：AES/CBC/ISO10126Padding
	            // 对于XML的加密，JCE需要支持ACE（128/256），并使用ISO10126Padding（填充位）
	            javaCryptoValidationInitializer.init();
	        } catch (InitializationException e) {
	            e.printStackTrace();
	        }

	        //打印当前已经被安装的所有JCE的provider
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
		   //如果已经认证了，则直接允许访问
		   if(httpServletRequest.getSession().getAttribute(SPMetadata.AUTHENTICATED_SESSION_ATTRIBUTE)!=null) {
			   chain.doFilter(request, response);
		   }else {
			   //保存这次访问的URL，供认证后重定向
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

	        //关于传输对端实体的信息，对于IDP就是SP，对于SP就是IDP；
	        SAMLPeerEntityContext peerEntityContext =
	                context.getSubcontext(SAMLPeerEntityContext.class, true);

	        //端点信息；
	        SAMLEndpointContext endpointContext =
	                peerEntityContext.getSubcontext(SAMLEndpointContext.class, true);
	        endpointContext.setEndpoint(getIPDEndpoint());

	        //数据签名环境上线文
	        SignatureSigningParameters signatureSigningParameters = new SignatureSigningParameters();
	        //获得证书，其中包含公钥
	        signatureSigningParameters.setSigningCredential(SPCredentials.getCredential());
	        //ALGO_ID_SIGNATURE_RSA_SHA256
	        signatureSigningParameters.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);


	        context.getSubcontext(SecurityParametersContext.class, true)
	                .setSignatureSigningParameters(signatureSigningParameters);

	        // OpenSAML提供了HTTPRedirectDefalteEncoder
	        // 它将帮助我们来对于AuthnRequest进行序列化和签名
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
	            //*encode*方法将会压缩消息，生成签名，添加结果到URL并从定向用户到Idp.
	            //先使用RFC1951作为默认方法压缩数据，在对压缩后的数据信息Base64编码
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
	        //请求时间：该对象创建的时间，以判断其时效性
	        authnRequest.setIssueInstant(new DateTime());
	        //目标URL：目标地址，IDP地址
	        authnRequest.setDestination(getIDPSSOURL());
	        //传输SAML断言所需要的绑定：也就是用何种协议使用Artifact来取回真正的认证信息，
	        authnRequest.setProtocolBinding(SAMLConstants.SAML2_ARTIFACT_BINDING_URI);
	        //SP地址： 也就是SAML断言返回的地址
	        authnRequest.setAssertionConsumerServiceURL(getAssertionConsumerURL());
	        //请求的ID：为当前请求设置ID，一般为随机数
	        authnRequest.setID(OpenSAMLUtils.generateSecureRandomId());
	        //Issuer： 发行人信息，也就是SP的ID，一般是SP的URL
	        authnRequest.setIssuer(buildIssuer());
	        //NameID：IDP对于用户身份的标识；NameID policy是SP关于NameID是如何创建的说明
	        authnRequest.setNameIDPolicy(buildNameIdPolicy());
	        // 请求认证上下文（requested Authentication Context）:
	        // SP对于认证的要求，包含SP希望IDP如何验证用户，也就是IDP要依据什么来验证用户身份。
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
