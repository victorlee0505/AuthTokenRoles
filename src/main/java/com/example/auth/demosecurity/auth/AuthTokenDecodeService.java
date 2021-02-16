package com.example.auth.demosecurity.auth;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.TimeZone;

import javax.servlet.http.HttpServletRequest;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeType;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Service;

/**
 * Handling token process, mainly extract custom claims with role and
 * permission.
 */
@Service
public class AuthTokenDecodeService {
    
    private static final Logger LOG = LoggerFactory.getLogger(AuthTokenDecodeService.class);

    // Custom Claims in Token Payload other than "scope"
    // role have permissions: Admin has many permissions , User has a few permissions
    public static final String KEY_ROLES = "roles";
    public static final String KEY_PERMISSIONS = "permissions";
    public static final String KEY_CLIENTID = "clientId";

    // permission prefix 
    // ex. MyApp - RolePermission - API
    // myapp.rp.api1
    public static final String MYAPP_RP = "myapp.rp.";

    /**
     * Retrieve Token from Header
     * @param request
     * @return jwt as string
     */
    public String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    /**
     * Decode Token with custom claims
     * @param token
     * @return DecodedAuthToken
     */
    public DecodedAuthToken decode(String token) {

        if (StringUtils.isNotBlank(token)) {
            DecodedJWT jwt = JWT.decode(token);

            byte[] decodedPayload = Base64.getDecoder().decode(jwt.getPayload());
            DecodedAuthToken dToken = customClaimParser(new String(decodedPayload));

            if (dToken != null) {
                dToken.setClient_Id(jwt.getSubject());
                dToken.setIssuer(jwt.getIssuer());
                dToken.setAudience(jwt.getAudience());
                dToken.setIssuedAt(LocalDateTime.ofInstant(jwt.getIssuedAt().toInstant(), TimeZone.getTimeZone("America/New_York").toZoneId()));
                dToken.setExpiresAt(LocalDateTime.ofInstant(jwt.getExpiresAt().toInstant(), TimeZone.getTimeZone("America/New_York").toZoneId()));
            } else {
                return null;
            }

            return dToken;
        }
        return null;
    }

    /**
     * Extract custom claim from decoded JWT Payload String
     * @param payload
     * @return DecodedAuthToken w or w/o roles and permissions
     */
    private DecodedAuthToken customClaimParser(String payload) {

        DecodedAuthToken dToken = new DecodedAuthToken();

        JsonNode rootNode = parsingNode(payload);
        JsonNode roleNode = rootNode.get(KEY_ROLES);
        JsonNode permNode = rootNode.get(KEY_PERMISSIONS);
        JsonNode idNode = rootNode.get(KEY_CLIENTID);

        if(roleNode != null && roleNode.getNodeType() != JsonNodeType.NULL){
            dToken.setRoles(Arrays.asList(StringUtils.split(StringUtils.remove(roleNode.toString(), "\""), ",")));
        }

        if(permNode != null && permNode.getNodeType() != JsonNodeType.NULL){
            dToken.setPermissions(Arrays.asList(StringUtils.split(StringUtils.remove(permNode.toString(), "\""), ",")));
        }

        if(idNode != null && idNode.getNodeType() != JsonNodeType.NULL){
            dToken.setClient_Id(idNode.toString());
        }

        return dToken;
    }

    /**
     * Parsing JSON as a Tree
     * 
     * @param body
     * @return
     */
    public JsonNode parsingNode(String body) {

        JsonFactory factory = new JsonFactory();
        ObjectMapper mapper = new ObjectMapper(factory);
        JsonNode rootNode;
        try {
            rootNode = mapper.readTree(body);
            return rootNode;
        } catch (JsonMappingException e) {
            LOG.error("JsonMappingException", e);
        } catch (JsonProcessingException e) {
            LOG.error("JsonProcessingException", e);
        }

        return null;
    }

    /**
     * assign permission to user
     * @param dToken
     * @return UsernamePasswordAuthenticationToken
     */
    public UsernamePasswordAuthenticationToken authenticateUserRole(DecodedAuthToken dToken) {

        Set<SimpleGrantedAuthority> authorities = getGrantedAuthority(dToken);
        User principal = new User(dToken.getClient_Id(), "", authorities);
        return new UsernamePasswordAuthenticationToken(principal, "", authorities);
    }

    /**
     * Create a SET of ROLE_{api}
     * @param dToken
     * @return
     */
    private Set<SimpleGrantedAuthority> getGrantedAuthority(DecodedAuthToken dToken) {
        Set<SimpleGrantedAuthority> authorities = new HashSet<>();
        List<String> permissions = dToken.getPermissions();

        if (!permissions.isEmpty()) {
            for (String perm : permissions) {
                if (StringUtils.startsWithIgnoreCase(perm, MYAPP_RP)) {
                    String api = StringUtils.removeStartIgnoreCase(perm, MYAPP_RP);
                    authorities.add(new SimpleGrantedAuthority("ROLE_" + api));
                }
            }
        }
        return authorities;
    }
}

