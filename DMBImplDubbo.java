package cn.sunline.ltts.dmb.impl.dubbo;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Future;

import cn.sunline.ltts.dmb.*;
import cn.sunline.ltts.dmb.impl.dubbo.config.ResponseCode;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;

import com.alibaba.dubbo.config.ProtocolConfig;
import com.alibaba.dubbo.config.ServiceConfig;
import com.alibaba.dubbo.monitor.Monitor;
import com.alibaba.dubbo.monitor.support.AbstractMonitorFactory;
import com.alibaba.dubbo.rpc.RpcContext;
import com.alibaba.fastjson.JSONObject;

import cn.sunline.ltts.dmb.impl.dubbo.config.DMBDubboConf;
import cn.sunline.ltts.dmb.impl.dubbo.config.DMBDubboSingleConf;
import cn.sunline.ltts.dmb.impl.dubbo.registry.RegistryCenter;
import cn.sunline.ltts.dmb.impl.dubbo.registry.RegistryHandle;
import cn.sunline.ltts.dmb.impl.dubbo.registry.ZookeeperRegistry;
import cn.sunline.ltts.dmb.impl.dubbo.registry.data.Config;
import cn.sunline.ltts.dmb.impl.dubbo.registry.data.RegistryCache;
import cn.sunline.ltts.dmb.impl.dubbo.registry.handle.support.ExportHandle;
import cn.sunline.ltts.dmb.impl.dubbo.registry.manager.RegistryMng;
import cn.sunline.ltts.dmb.impl.dubbo.util.DMBDubboConfUtil;
import cn.sunline.ltts.dmb.impl.dubbo.util.DubboUtil;
import cn.sunline.ltts.dmb.impl.dubbo.util.IpFilterUtil;
import cn.sunline.ltts.dmb.model.DMBDestination;
import cn.sunline.ltts.dmb.model.DMBHandler;
import cn.sunline.ltts.dmb.model.DMBRequest;
import cn.sunline.ltts.dmb.model.DMBResponse;
import cn.sunline.ltts.dmb.model.DMBService;

public class DMBImplDubbo extends DMB {
    private static final Logger LOGGER = LogManager.getLogger(DMBImplDubbo.class);

    protected DMBImplDubbo(DMBFacotry factory) {
        super(factory);
    }

    // 2016.5.29 解决并发问题
    private Map<String, ServiceConfig> serviceBuff = new ConcurrentHashMap<String, ServiceConfig>(); // 缓存服务代理对象
    private Map<String, IDMBDubboService> consumerBuff = new ConcurrentHashMap<String, IDMBDubboService>(); // 缓存服务代理对象

    private Object holdObj = new Object();
    private Thread holdThread = new Thread(new Runnable() {
        @Override
        public void run() {
            try {
                synchronized (holdObj) {
                    holdObj.wait();
                }
            } catch (InterruptedException e) {
            }
        }
    }, "DMB-Hold-Thread");

    private DMBConfManager confManager = null;

    @Override
    public DMBResponse doSendSync(DMBRequest request) {
        registerConsumer(request.getDestination().getDmbService());
        DMBResponse ret = consumerBuff.get(DubboUtil.getDubboGroup(request.getDestination())).call(request);
        ret = failoverRetry(request, ret);
        return ret;
    }

    @Override
    public DMBFuture doSendAsync(DMBRequest request) {
    	//异步调用，设置异步方式
    	request.getDestination().getDmbService().setSync(false);
        registerConsumer(request.getDestination().getDmbService());
        
        consumerBuff.get(DubboUtil.getDubboGroup(request.getDestination())).call(request);
        
        Future<DMBResponse> future = RpcContext.getContext().getFuture();
        
        DMBFuture dmbFuture = new DMBFuture(request);
        dmbFuture.setFuture(future);
        return dmbFuture;
    }
    
    
    
    @Override
    public void registProviders(DMBHandler[] handlers) {
        for (DMBHandler handler : handlers) {
            registProvider(handler);
        }
        if (serviceBuff != null && !serviceBuff.isEmpty()) {
        	synchronized (this) {
            if (!holdThread.isAlive()) {
                holdThread.setDaemon(false);
                holdThread.start();
        	}
        	}
        }
    }

    public void registProvider(DMBHandler handler) {
        String serviceKey = DubboUtil.getDubboGroup(handler.getDest());
        // 2016.5.26 解决并发问题
        synchronized (serviceBuff) {
            // 2016.5.26 再次判断下
            if (!serviceBuff.containsKey(serviceKey)) {
                //获取当前注册服务的配置
                Map confMap = getConfManager().getProviderConf(handler.getDest().getDmbService().getServiceOrEventId());
                DMBDubboSingleConf singleConf = getSingleConf(confMap);

                if(DMBDubboConstants.TRUE_KEY.equals(DMBDubboConf.getServiceControl()) || 
                		DMBDubboConstants.TRUE_KEY.equals(DMBDubboConf.getServiceIpControl())){
                	registryInit(handler.getDest());
                	
                	 //校验服务发布权限，默认不开启
                    if (DMBDubboConstants.TRUE_KEY.equals(DMBDubboConf.getServiceControl())) {
                        if (RegistryCache.getServiceList() != null) {
                            String serviceName = getServiceName(handler);
                            if (!RegistryCache.getServiceList().contains(serviceName)) {
                                throw new DMBException("The service " + serviceName + " has no privilege to release！");
                            }
                        } else {
                            throw new DMBException("None of services has  privilege to release！");
                        }
                        	if(LOGGER.isInfoEnabled()){
                        		LOGGER.info("服务["+serviceKey +"]注册权限校验成功");
                        	}
                       
                    }
                  //校验系统IP服务发布权限
                    if(DMBDubboConstants.TRUE_KEY.equals(DMBDubboConf.getServiceIpControl())){
                    	 //获取服务端配置数据
                        String proIpWhiteLists = RegistryCache.getRegistryConfigs().get(serviceKey).getProviderIpWhiteLists();
                         //IP校验
                       boolean IpCheck = IpFilterUtil.checkLoginIP(DubboUtil.getLocalIp(), IpFilterUtil.init(proIpWhiteLists));
                        if(!IpCheck){
                        	throw new DMBException("Register error！服务发布失败，当前系统IP 没有权限注册服务： " + serviceKey + " ！"
                        			+ "有权限的网段：" +proIpWhiteLists +"， 当前IP："+ DubboUtil.getLocalIp());
                        }else{
                     	   if(LOGGER.isInfoEnabled()){
                        		LOGGER.info("服务["+serviceKey +"]IP权限校验成功");
                        	}
                        }
                    }
                	
                }else {
                	LOGGER.info("权限发布校验与系统IP校验未开启");
                }
               
                
                
                ServiceConfig service = DubboUtil.registDubboService(handler, singleConf);
                serviceBuff.put(DubboUtil.getDubboGroup(handler.getDest()), service);
            } // if
        } // synchronized
    }

    /**
     * sunline-mod pb 20160229 多消费者注册,生成代理实例并放入缓存
     * 
     * @author Pengbin
     * @param DMBDestination[]
     * @return void
     * 
     */
    @Override
    public void registConsumers(DMBService[] services) {
        for (DMBService service : services) {
            registerConsumer(service);
        }
        if (consumerBuff != null && !consumerBuff.isEmpty()) {
        	synchronized (this) {
            if (!holdThread.isAlive()) {
                holdThread.setDaemon(false);
                holdThread.start();
            }
        }
        	}
    }

    /**
     * sunline-mod pb 20160229 消费者注册,生成代理实例并放入缓存
     * 
     * @author Pengbin
     * @param DMBDestination
     * @return void
     * 
     */
    public void registerConsumer(DMBService service) {
        DMBDestination dest = new DMBDestination(service);
        String consumerKey = DubboUtil.getDubboGroup(dest);

        // TODO 对象订阅失败的情况下如何处理,目前直接由dubbo中抛出异常
        if (!consumerBuff.containsKey(consumerKey)) {
            // 2016.5.26 解决并发问题
            synchronized (consumerBuff) {
                // 2016.5.26 再次判断下
                if (!consumerBuff.containsKey(consumerKey)) {
                    //获取当前注册服务的配置
                    Map confMap = getConfManager().getCustomerConf(service.getServiceOrEventId());
                    DMBDubboSingleConf singleConf = getSingleConf(confMap);

                    if(DMBDubboConstants.TRUE_KEY.equals(DMBDubboConf.getReferenceControl()) || 
                    		DMBDubboConstants.TRUE_KEY.equals(DMBDubboConf.getReferenceIpControl())){
                        registryInit(dest);
                        //开启消费权限验证
                        if (DMBDubboConstants.TRUE_KEY.equals(DMBDubboConf.getReferenceControl())) {
      
                            String consumerPath = RegistryMng.toConsumerPath(service, singleConf.getDubboSingleConfObj()); //获取消费权限存储路径
                            if (consumerPath != null) {
                                //从注册中心获取节点服务下对应有消费权限的系统编码。
                                List<String> consumerList = (List<String>) RegistryMng.getCenter().getRegistry().lookupData(consumerPath);
                                if (consumerList == null) {
                                    throw new DMBException("Register error！None of consumers has privilege to consume the service " + consumerKey + " ！ Please apply it！");
                                } else if (!consumerList.contains(DMBDubboConf.getSystemId())) {
                                    throw new DMBException("Register error！The system has no privilege to consume the service " + consumerKey + " ！ Please apply it！");
                                }else{
                                	if(LOGGER.isInfoEnabled()){
                                		LOGGER.info("消费访问服务["+consumerKey +"]权限校验成功");
                                	}
                                }
                            }
                        }
                      //开启IP网段验证
                        if(DMBDubboConstants.TRUE_KEY.equals(DMBDubboConf.getReferenceIpControl())){
                        	//获取当前IP,并判断
                            boolean IpCheck = IpFilterUtil.checkLoginIP(DubboUtil.getLocalIp(), RegistryCache.getIpWhiteList(consumerKey));
                            if(!IpCheck){
                            	throw new DMBException("Register error！当前系统IP 没有权限消费服务： " + consumerKey + " ！"
                            			+ "有权限的网段：" +RegistryCache.getRegistryConfigs().get(consumerKey).getConsumerIpWhiteLists()+"， 当前IP："+ DubboUtil.getLocalIp());
                            }else{
                            	if(LOGGER.isInfoEnabled()){
                            		LOGGER.info("系统IP消费服务["+consumerKey +"]权限校验成功");
                            	}
                            }
                        }
                    }else{
                    	if(LOGGER.isInfoEnabled()){
                    	LOGGER.info("服务消费权限校验以及系统IP校验功能未开启");
                    	}
                    }
                    
                  
                    IDMBDubboService demoService = DubboUtil.refer(dest, singleConf); // 此代理对象内部封装了所有通讯细节，对象较重，需缓存复用
                    
                    
                    // 2016.5.26 放入缓存避免重复注册
                    consumerBuff.put(consumerKey, demoService);
                } // if
            }

        }
    }

    //TODO 该shutdown被加入了DMB的钩子中，主动调用该方法后，在jvm退出时会再执行一次
    @Override
    public void shutdown() {
    	
        if (LOGGER.isInfoEnabled()) {
            LOGGER.info("销毁释放dmb内部相关资源");
        }
        ProtocolConfig.destroyAll();
        for (Monitor mo : AbstractMonitorFactory.getMonitors()) {
            mo.destroy();
        }
        
        //清空缓存数据
        serviceBuff.clear();
        consumerBuff.clear();
        
        if (LOGGER.isInfoEnabled()) {
            LOGGER.info("interrupt DMB-hold-Thread");
        }
        holdThread.interrupt();
        
        
        
        /**避免在虚拟机关闭阶段依然增加钩子导致抛出异常**/
        	boolean hookCheck=true;
        try {
        	Thread checkThread = new Thread();
        	Runtime.getRuntime().addShutdownHook(checkThread);
        	Runtime.getRuntime().removeShutdownHook(checkThread);
		} catch (IllegalStateException e) {
			// TODO: handle exception
			hookCheck=false;
		}
        if(hookCheck){
        	try {
                final Class<?> clazz = Class.forName("com.alibaba.dubbo.remoting.transport.netty.NettyClient");
                Field field = clazz.getDeclaredField("channelFactory");
                field.setAccessible(true);
                Object channelFactory = field.get(null);
                Method method = channelFactory.getClass().getMethod("releaseExternalResources");
                method.invoke(channelFactory);
            }  catch (ClassNotFoundException e ) {
                LOGGER.warn("DMB shutdown warn！当前应用可能没有过消费行为");
            } catch (Exception e) {
    			// TODO: handle exception
    		}
        }
        
        
        

    }

    public DMBConfManager getConfManager() {
        if (confManager == null) {
            confManager = DMBDubboConfUtil.getConfMng();
        }
        return confManager;
    }

    /**
     * sunline-mod 20160414 PB
     * 获取指定服务的配置对象
     */
    private DMBDubboSingleConf getSingleConf(Map confMap) {
        return new DMBDubboSingleConf(confMap);

    }

    /***
     * sunline-mod 20160520 PB
     * 初始化dmb注册中心连接，方便进行权限相关参数的查询
     ***/
    protected void registryInit(DMBDestination dest) {
    	String serviceKey = DubboUtil.getDubboGroup(dest);
        RegistryCenter registryCenter = RegistryMng.getCenter();
        
        ZookeeperRegistry registry = registryCenter.getRegistry();
        RegistryHandle handle= new ExportHandle();
        
        
        if (!registryCenter.isAvailable()) {     //注册中心第一次启动 
           
        	 registryCenter.start();    //启动注册中心
        	 registry=registryCenter.getRegistry();
             //查询可发布服务列表，并缓存
             List<String> serviceList = registry.lookupNode(RegistryMng.toRootPath());
             if (serviceList != null) {
             	RegistryCache.setServiceList(serviceList);
             }
             //对根节点下的服务进行订阅
             registry.doSubscribe(handle);
        }
        
        if(DMBDubboConstants.TRUE_KEY.equals(DMBDubboConf.getReferenceIpControl()) ||
        		DMBDubboConstants.TRUE_KEY.equals(DMBDubboConf.getServiceIpControl())){
        	
        String configPath = RegistryMng.toConfigPath(dest.getDmbService()); //获取服务配置路径
        //从注册中心获取节点服务下对应有消费权限的IP网段。
        String config = (String) RegistryMng.getCenter().getRegistry().lookupData(configPath);
        if(config==null){
        	throw new DMBException("获取服务 ["+serviceKey+"] config配置信息失败，请检查申请信息");
        }
        try {
            //查询可发布服务配置数据
            Config registryConfig = JSONObject.parseObject(config, Config.class);
            //缓存配置
            RegistryCache.getRegistryConfigs().put(serviceKey, registryConfig);
            
            if(DMBDubboConstants.TRUE_KEY.equals(DMBDubboConf.getReferenceIpControl())){
            //初始化注册中心消费白名单
            RegistryCache.initIpWhiteList(serviceKey, registryConfig.getConsumerIpWhiteLists());
            
            }
            registry.doDataSubscribe(serviceKey, handle);
            //TODO 如果注册中心启动失败，则读取文件缓存进行设置
		} catch (Exception e) {
			throw new DMBException("初始化服务配置失败，cause：",e);
		}
        }

    }




    //获取权限中的服务名
    private String getServiceName(DMBHandler handler) {
        return DubboUtil.getDubboGroup(handler.getDest());
    }



    //失败重试
    private DMBResponse failoverRetry(DMBRequest request, DMBResponse response) {
        if(!ResponseCode.EXCEPTION_KEY.equals(response.getRetCode())){
                return  response;
        }
        if (!"".equals(DMBDubboConf.getRetryCount())){
            int retry = 0;
            try {
                retry = Integer.valueOf(DMBDubboConf.getRetryCount());
            }catch (Exception e){
                throw new DMBException("调用异常，DMB失败重试次数格式不正确，请填数字，retryCount=" + DMBDubboConf.getRetryCount());
            }
            for (int i = 0; i < retry; i++){
                DMBResponse ret = consumerBuff.get(DubboUtil.getDubboGroup(request.getDestination())).call(request);
                if(!ResponseCode.EXCEPTION_KEY.equals(ret.getRetCode())){
                    return  ret;
                }
            }
        }
        return response;
    }


}
