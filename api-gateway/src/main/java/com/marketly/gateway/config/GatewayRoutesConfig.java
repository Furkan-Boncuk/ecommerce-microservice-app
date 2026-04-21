package com.marketly.gateway.config;

import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class GatewayRoutesConfig {

    @Bean
    public RouteLocator routeLocator(RouteLocatorBuilder builder) {
        return builder.routes()
                .route("auth-service", route -> route.path("/api/v1/auth/**")
                        .uri("http://localhost:8081"))
                .route("product-service", route -> route.path("/api/v1/products/**")
                        .uri("http://localhost:8082"))
                .route("order-service-cart", route -> route.path("/api/v1/cart/**")
                        .uri("http://localhost:8083"))
                .route("order-service-orders", route -> route.path("/api/v1/orders/**")
                        .uri("http://localhost:8083"))
                .build();
    }
}
