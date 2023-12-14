namespace Paket

open System
open System.IO
open Newtonsoft.Json

type CredentialProviderResponseCode = 
    | Success = 0
    | Error = 1
    | NotFound = 2

// https://github.com/NuGet/NuGet.Client/blob/e8b43e6602749844de42f9f37e07fa9aa1fb108c/src/NuGet.Core/NuGet.Protocol/Plugins/Messages/GetCredentialsResponse.cs#L43
type CredentialProviderResultMessage =
    {
      [<JsonProperty("ResponseCode")>]
      ResponseCode : CredentialProviderResponseCode;
      [<JsonProperty("Username")>]
      Username : string;
      [<JsonProperty("Password")>]
      Password : string;
      [<JsonProperty("Message")>]
      Message  : string
      [<JsonProperty("AuthenticationTypes")>]
      AuthTypes : string [] }

    member this.IsValid : bool = true
        //! NOTE: azure-credprovider does this, but I haven't seen it yet in response json
        // Enum.IsDefined(typeof<CredentialProviderResponseCode>, this.ResponseCode) 

type CredentialProviderExitCode =
    | Success = 0
    | ProviderNotApplicable = 1
    | Abort = 2

type CredentialProviderResult =
    | Success of UserPassword list
    | NoCredentials of string
    | Abort of string

type CredentialProviderOutputFormat =
    | HumanReadable
    | Json

type CredentialProviderVerbosity =
    | Debug
    | Verbose
    | Information
    | Minimal
    | Warning
    | Error

type CredentialProviderParameters =
    { Uri : string
      NonInteractive : bool
      CanShowDialog : bool
      IsRetry : bool
      Verbosity : CredentialProviderVerbosity }

/// Exception for request errors
#if !NETSTANDARD1_6
[<System.Serializable>]
#endif
type CredentialProviderUnknownStatusException =
    inherit Exception
    new (msg:string, inner:exn) = {
      inherit Exception(msg, inner) }
#if !NETSTANDARD1_5
    new (info:System.Runtime.Serialization.SerializationInfo, context:System.Runtime.Serialization.StreamingContext) = {
      inherit Exception(info, context)
    }
#endif

module CredentialProviders =
    open Logging
    open System.Collections.Concurrent

    // See https://learn.microsoft.com/en-us/nuget/reference/extensibility/nuget-cross-platform-plugins#plugin-installation-and-discovery
    let pluginPattern = "CredentialProvider*.dll"
    let envVars =
        [|
            "NUGET_NETCORE_PLUGIN_PATHS"
            "NUGET_PLUGIN_PATHS"
        |]
    let directoryRoot =
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".nuget", "plugins", "netcore")
    let findAll rootPath customPaths assemblyPattern paketDirectoryAssemblyPattern =
        let directories =
            [ yield! customPaths
              yield rootPath ]
        [ yield!
            directories
            |> Seq.filter Directory.Exists
            |> Seq.collect (fun d -> Directory.EnumerateFiles(d, assemblyPattern, SearchOption.AllDirectories))
          let paketDirectory = Path.GetDirectoryName(typeof<CredentialProviderUnknownStatusException>.Assembly.Location)
          if not (String.IsNullOrEmpty paketDirectory) then
            yield! Directory.EnumerateFiles(paketDirectory, paketDirectoryAssemblyPattern)
        ]
    let findPathsFromEnvVar key =
        let paths = Environment.GetEnvironmentVariable key
        if not (String.IsNullOrEmpty paths) then
            paths.Split([|';'|], StringSplitOptions.RemoveEmptyEntries)
            |> Array.toList
        else [ ]

    let collectProviders () =
        let customPaths = envVars |> Seq.collect (fun v -> findPathsFromEnvVar v)
        findAll directoryRoot customPaths pluginPattern pluginPattern
        |> List.distinct

    // See https://github.com/NuGet/NuGet.Client/blob/c17547b5c64ab8d498cc24340a09ae647456cf20/src/NuGet.Clients/NuGet.Credentials/PluginCredentialProvider.cs#L169
    let formatCommandLine args =
        [
            yield! ["-Uri"; args.Uri]
            yield! ["-OutputFormat"; CredentialProviderOutputFormat.Json.ToString() ]
            if args.NonInteractive then yield! ["-NonInteractive"; args.NonInteractive.ToString()]
            if args.CanShowDialog then yield! ["-CanShowDialog"; args.CanShowDialog.ToString()]
            if args.IsRetry then yield! ["-IsRetry"; args.IsRetry.ToString()]
            if args.Verbosity <> CredentialProviderVerbosity.Information then
                yield! ["-Verbosity"; args.Verbosity.ToString()]
        ]
        |> Seq.map (fun arg -> if arg.Contains " " then failwithf "cannot contain space" else arg)
        |> String.concat " "

    let private availableAuthTypes =
        [ AuthType.Basic; AuthType.NTLM ]
        |> List.map (fun t -> t.ToString().ToLower(), t)
    let callProvider provider args =
        let cmdLine = formatCommandLine args
        let procResult =
            ProcessHelper.ExecProcessAndReturnMessages (fun info ->
              info.FileName <- provider
              info.WindowStyle <- System.Diagnostics.ProcessWindowStyle.Hidden
              info.ErrorDialog <- false
              info.Arguments <- cmdLine) (TimeSpan.FromMinutes 10.)

        let stdError = ProcessHelper.toLines procResult.Errors
        for line in procResult.Errors do
            Logging.traceVerbose (sprintf "%s: %s" provider line)

        let json = ProcessHelper.toLines procResult.Messages
        let credentialResponse =
            try
                JsonConvert.DeserializeObject<CredentialProviderResultMessage>(json)
            with e ->
                raise <| exn(sprintf "Credential provider returned an invalid result: %s\nError: %s" json stdError, e)
        let parsableResult = not (isNull (box credentialResponse))
        let validResult = parsableResult && credentialResponse.IsValid

        match enum procResult.ExitCode with
        | CredentialProviderExitCode.Success when validResult ->
            let createResult auth =
                {Username = credentialResponse.Username; Password = credentialResponse.Password; Type = auth }
            let results =
                if isNull (box credentialResponse.AuthTypes) || credentialResponse.AuthTypes.Length = 0 then
                    [createResult AuthType.Basic]
                else
                    let results =
                        credentialResponse.AuthTypes
                        |> List.ofArray
                        |> List.map (fun tp -> tp.ToLower())
                        |> List.map (fun tp ->
                            match availableAuthTypes |> List.tryFind (fun (s, _) -> s = tp) with
                            | Some (_, matching) ->
                                tp, Some (createResult matching)
                            | None ->
                                tp, None)
                    if results |> List.exists (snd >> Option.isSome) then
                        results |> List.choose snd
                    else
                        for tp, _ in results do
                            Logging.traceWarnfn "The authentication scheme '%s' is not supported" tp
                        []
            Success results
        | CredentialProviderExitCode.Success ->
            failwithf "Credential provider returned an invalid result (%d): %s\n Standard Error: %s" procResult.ExitCode json stdError
        | CredentialProviderExitCode.ProviderNotApplicable ->
            NoCredentials (if parsableResult then credentialResponse.Message else "")
        | CredentialProviderExitCode.Abort ->
            let msg = if parsableResult then credentialResponse.Message else ""
            Abort (sprintf "\"'%s' %s\":%s\nStandard Error: %s" provider cmdLine msg stdError)
        | _ ->
            raise <| CredentialProviderUnknownStatusException (sprintf "Credential provider returned an invalid result (%d): %s\nStandard Error: %s" procResult.ExitCode json stdError, (null : exn))

    let private  _providerCredentialCache = new ConcurrentDictionary<string, CredentialProviderResult>()
    let private getKey provider source =
        provider + "_" + source
    let handleProvider isRetry provider source =
        let key = getKey provider source
        let args =
            { Uri = source
              NonInteractive = not Environment.UserInteractive
              IsRetry = isRetry
              CanShowDialog = Environment.UserInteractive
              Verbosity = CredentialProviderVerbosity.Information }
        match _providerCredentialCache.TryGetValue key with
        | true, v when not isRetry ->
            v
        | _ ->
          // Only ever show a single provider at the same time.
          lock _providerCredentialCache (fun _ ->
            match _providerCredentialCache.TryGetValue key with
            | true, v when not isRetry ->
                v
            | _ ->
                Logging.verbosefn "Calling provider '%s' for credentials" provider
                let result =
                    try callProvider provider args
                    with :? CredentialProviderUnknownStatusException when args.Verbosity <> CredentialProviderVerbosity.Information ->
                        // https://github.com/NuGet/NuGet.Client/blob/c17547b5c64ab8d498cc24340a09ae647456cf20/src/NuGet.Clients/NuGet.Credentials/PluginCredentialProvider.cs#L117
                        callProvider provider { args with Verbosity = CredentialProviderVerbosity.Information }

                match result with
                | CredentialProviderResult.Abort _ -> ()
                | _ ->
                    _providerCredentialCache.[key] <- result

                result)

    let GetAuthenticationDirect (source : string) isRetry =
        collectProviders()
        |> List.collect (fun provider ->
            match handleProvider isRetry provider source with
            | CredentialProviderResult.Success l -> l
            | CredentialProviderResult.NoCredentials _ -> []
            | CredentialProviderResult.Abort msg -> failwith msg)

    let GetAuthenticationProvider source =
        AuthProvider.ofFunction (fun isRetry ->
            match GetAuthenticationDirect source isRetry with
            | h :: _ -> Some (Credentials h)
            | _ -> None)

