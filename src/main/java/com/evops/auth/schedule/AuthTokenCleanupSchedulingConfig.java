package com.evops.auth.schedule;

import com.evops.auth.jwt.JwtProperties;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.quartz.CronTriggerFactoryBean;
import org.springframework.scheduling.quartz.MethodInvokingJobDetailFactoryBean;

/**
 * 令牌清理定时作业装配：JobDetail + Trigger，Scheduler 由 Spring Boot 自动收集 Trigger。
 * 测试环境用 auth.jwt.scheduling-enabled=false 关闭。
 */
@Configuration
@ConditionalOnProperty(prefix = "auth.jwt", name = "scheduling-enabled", havingValue = "true",
        matchIfMissing = true)
public class AuthTokenCleanupSchedulingConfig {

    @Bean
    public MethodInvokingJobDetailFactoryBean authTokenCleanupJobDetail(
            AuthTokenCleanupScheduler scheduler) {
        MethodInvokingJobDetailFactoryBean factory = new MethodInvokingJobDetailFactoryBean();
        factory.setTargetObject(scheduler);
        factory.setTargetMethod("runCleanup");
        factory.setConcurrent(false);
        factory.setName("authTokenCleanupJobDetail");
        return factory;
    }

    @Bean
    public CronTriggerFactoryBean authTokenCleanupTrigger(
            MethodInvokingJobDetailFactoryBean authTokenCleanupJobDetail,
            JwtProperties properties) {
        CronTriggerFactoryBean factory = new CronTriggerFactoryBean();
        factory.setJobDetail(authTokenCleanupJobDetail.getObject());
        factory.setCronExpression(properties.getCleanupCron());
        factory.setName("authTokenCleanupTrigger");
        return factory;
    }
}
