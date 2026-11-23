import * as BunnySDK from "@bunny.net/edgescript-sdk";
import { runtimeProbe } from "./probe.ts";

BunnySDK.net.http.serve(runtimeProbe);
