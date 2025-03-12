# Mulesoft Flex Phantom Token Policy
[![Quality](https://img.shields.io/badge/quality-experiment-red)](https://curity.io/resources/code-examples/status/)
[![Availability](https://img.shields.io/badge/availability-source-blue)](https://curity.io/resources/code-examples/status/)

A custom policy for the Mulesoft Flex Gateway to introspect opaque access tokens and forward JWTs to APIs following the [Phantom Token Pattern](https://curity.io/resources/learn/phantom-token-pattern/).

## Overview
Although the Mulesoft Flex API Gateway has built-in policies for both JWT validation and OAuth Introspection it lacks the capability of receiving an opaque access token and introspecting that to obtain a JWT. This project leverages the Mulesoft Flex API Gateway Policy Development Kit (PDK) to provide that capability.

This custom policy can be configured to use either the `application/jwt` approach where the JWT is available directly in the introspection response or alternatively use a standard introspection call where the JWT is available in the `phantom_token` claim. Both methods are detailed in the [OAuth Introspection and Phantom Tokens](https://curity.io/resources/learn/introspect-with-phantom-token/) article.

This plugin also has a set of configurations that enforces validation of the `iss`, `aud` and optionally `scope` claims.

## Prerequisites
Prerequisites for developing custom policies using the Mulesoft Flex Gateway PDK are outlined in the [Mulesoft documentation - Reviewing PDK Prerequisites](https://docs.mulesoft.com/pdk/latest/policies-pdk-prerequisites). 

This outline of [Developing Custom Policies](https://docs.mulesoft.com/pdk/latest/policies-pdk-develop-custom-policies) includes all the steps needed. This is a good reference to review before getting started.

> [!NOTE]
> This project is already prepared so that step 1, 2, and 3 should be possible to skip.

### Authentication to the Anypoint Platform CLI
To build, publish and release the custom policy, authentication to the Anypoint Platform CLI is needed. This can be achieved in a couple o different ways and is outlined in the [Mulesoft documentation - Authentication to the Anypoint Platform CLI](https://docs.mulesoft.com/anypoint-cli/latest/auth).

## Compiling the Policy
To compile the policy, make sure the prerequisites are met and then run:

`make build`

## Publishing the Policy
After successfully compiling the custom policy, publish it to the Mulesoft Exchange by executing:

`make publish`

## Configuration
Parameter | Description |
--------- | ----------- |
Introspection Endpoint | The introspection endpoint of The Curity Identity Server
Introspection Client | The client_id of a client with the `introspection` capability
Introspection Secret | The secret of the client with the `introspection` capability
Required Audience | The value of the `aud` claim in the token required for access
Required Issuer | The value of the `iss` claim in the token required for access
Required Scope(s) | Required scopes for API access (space separated string)
Use 'application/jwt' Header | Boolean value the configures if the `application/jwt` header approach should be used for introspection. This returns the JWT directly in the introspection response. 
Token Extractor | The method Mulesoft Flex uses to extract the token in the Authorization header. (Can typically be left as default)

## More Information
* Please visit [curity.io](https://curity.io/) for more information about the Curity Identity Server.
* [Flex Gateway Policy Development Kit (PDK) Overview](https://docs.mulesoft.com/pdk/latest/policies-pdk-overview)

Copyright (C) 2025 Curity AB.