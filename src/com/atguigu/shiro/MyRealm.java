package com.atguigu.shiro;

import javax.annotation.PostConstruct;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.realm.AuthenticatingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;
import org.springframework.stereotype.Component;

@Component
public class MyRealm extends AuthenticatingRealm {

	// 完成认证
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(
			AuthenticationToken authenticationToken)
			throws AuthenticationException {
		UsernamePasswordToken token = (UsernamePasswordToken) authenticationToken;
		// 获取页面输入的 username
		String username = token.getUsername();
		// 利用 username 查询数据表. 得到其所对应的记录的信息
		// principal: 登陆的实体信息
		Object principal = username;
		// 从数据表中获取的加密之后的密码信息
		Object hashedCredentials = "c00afc1b5f69fa94cc85b1beb8142751";
		// 盐值
		ByteSource credentialsSalt = ByteSource.Util.bytes("misaki");
		// 当前 Realm 的 name. 直接调用父类的 getName() 方法即可.
		String realmName = getName();
		SimpleAuthenticationInfo info = new SimpleAuthenticationInfo(principal,
				hashedCredentials, credentialsSalt, realmName);
		System.out.println("hello git");
		return info;
	}

	// 完成授权
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		Object principal = principals.getPrimaryPrincipal();
		System.out.println("授权: " + principal);

		// 根据 principal 获取用户所具有的权限. 并创建 AuthorizationInfo 对象, 返回
		SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
		info.addRole("user");
		if ("admin".equals(principal)) {
			info.addRole("admin");
		}
		return info;
	}

	// @PostConstruct 注解标记的方法相当于 init-method
	@PostConstruct
	public void initCredentialsMatcher() {
		// 创建 HashedCredentialsMatcher
		HashedCredentialsMatcher credentialsMatcher = new HashedCredentialsMatcher();
		// 设置 HashedCredentialsMatcher 的属性
		credentialsMatcher.setHashAlgorithmName("MD5");
		credentialsMatcher.setHashIterations(1024);
		// 把新创建的 HashedCredentialsMatcher bean 设置为当前 Realm 的 credentialsMatcher
		// 属性
		setCredentialsMatcher(credentialsMatcher);
	}

	public static void main(String[] args) {
		String algorithmName = "MD5";
		String source = "123";
		ByteSource salt = ByteSource.Util.bytes("misaki");
		int hashIterations = 1024;

		Object result = new SimpleHash(algorithmName, source, salt,
				hashIterations);
		System.out.println(result);
	}

}
