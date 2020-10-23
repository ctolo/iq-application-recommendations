#!/usr/bin/python3
# ----------------------------------------------------------------------------
# Python Dependencies
import datetime
import json
import argparse
import asyncio
import aiohttp

# ----------------------------------------------------------------------------
iq_url, iq_session = "", ""

def getArguments():
    global iq_url, iq_session, iq_auth
    parser = argparse.ArgumentParser(description='Export Reporting Recommendations')
    parser.add_argument('-i', '--publicId', help='PublicId for the Application', required=True)
    parser.add_argument('-s', '--stage', help='Stage of the scan', default="build", required=False)
    parser.add_argument('-u', '--url', help='', default="http://localhost:8070", required=False)
    parser.add_argument('-a', '--auth', help='', default="admin:admin123", required=False)
    args = vars(parser.parse_args())
    iq_url = args["url"]
    creds = args["auth"].split(":")
    iq_session = aiohttp.ClientSession()
    iq_auth = aiohttp.BasicAuth(creds[0], creds[1])
    return args

async def main():
    args = getArguments()
    publicId = args["publicId"]
    stage = args["stage"]

    application = await get_application(publicId)
    if application == None:
        print(f"Did not find application {publicId}")
        await iq_session.close()
        exit(1)

    applicationId = application["id"]
    print(f"Pulling recommendations for {publicId}")

    reportId = await get_reportId(applicationId, stage)
    report = await get_policy_violations(publicId, reportId)
    raw = await get_raw_report(publicId, reportId)
    report["reportTime"] = get_epoch(report["reportTime"])

    for component in report['components']:
        clean_dict(component, ["componentIdentifier","pathnames"])
        for violations in component["violations"]:
            clean_dict(violations, ["constraints"])
            violation = await get_violation(violations["policyViolationId"]) 
            
            r = violation["constraintViolations"][0]["reasons"][0]
            violation["reason"] = r["reason"] if r["reference"] is None else r["reference"]["value"]
            violation.update({"severity": None, "status": None})
            if violation["hash"] in raw.keys():
                if violation["reason"] in raw[violation["hash"]].keys():
                    violation.update( raw[violation["hash"]][violation["reason"]] )

            clean_dict(violation, ["displayName","constraintViolations","threatLevel","filename","componentIdentifier","applicationPublicId","applicationName","organizationName","stageData","policyOwner"])
            violations.update(violation)
        
    for resp in asyncio.as_completed([
            handle_component(component, applicationId, stage) for component in report['components']
            ]):
        await resp

    await iq_session.close()

    with open("results.json", "w+") as file:
        file.write(json.dumps(report, indent=4))
    print("Json results saved to -> results.json")

    csv = []
    for component in report['components']:
        for violation in component["violations"]:
            csv.append({
                "Application_Name": report["application"]["name"],
                "Application_ID": publicId,
                "Report_Type": stage,
                "Scan_Date": report["reportTime"],
                "Threat_Score": violation["policyThreatLevel"],
                "Policy": violation["policyName"],
                "Component_Name": component["displayName"],
                "Status": violation["status"],
                "next-no-violations": norm(component,"remediation","next-no-violations"), 
                "next-no-violations-with-dependencies": norm(component,"remediation","next-no-violations-with-dependencies"), 
            })

    with open("results.csv", "w+") as file:
        file.write(",".join(list(csv[0].keys()))+"\n")
        for c in csv:
            file.write(",".join( str(value) for value in c.values()  )+"\n")

    print("Json results saved to -> results.csv")

# -----------------------------------------------------------------------------
async def handle_component(component, applicationId, stage):
    if len(component["violations"]) > 0 and component["packageUrl"] != None:
        recommendation_task = asyncio.create_task( get_recommendation(component["packageUrl"], applicationId, stage) )
        recommendations = await recommendation_task

        print(f"Adding recommendations for {component['displayName']}")
        for change in recommendations["remediation"]["versionChanges"]:
            remediation = { change["type"]: change["data"]["component"]["packageUrl"]}
            recommendations["remediation"].update(remediation)
            change.pop("data", None)
        recommendations["remediation"].pop("versionChanges", None)
        component.update(recommendations)
    return True


def clean_dict(dictionary, remove_list):
    for e in remove_list: 
        dictionary.pop(e, None)

def norm(c, _1, _2):
    if _1 in c:
        if _2 in c[_1]:
            return c[_1][_2]
    return ""

async def handle_resp(resp, root=""):
    if resp.status != 200:
        print(await resp.text())
        return None
    node = await resp.json()
    if root in node:
        node = node[root]
    if node is None or len(node) == 0:
        return None
    return node

async def get_url(url, root=""):
    resp = await iq_session.get(url, auth=iq_auth)
    return await handle_resp(resp, root)

async def post_url(url, params, root=""):
    resp = await iq_session.post(url, json=params, auth=iq_auth)
    return await handle_resp(resp, root)


def get_epoch(epoch_ms):
    dt_ = datetime.datetime.fromtimestamp(epoch_ms/1000)
    return dt_.strftime("%Y-%m-%d %H:%M:%S")

async def get_application(publicId): # v.??
    url = f'{iq_url}/api/v2/applications?publicId={publicId}'
    apps = await get_url(url, "applications")
    if apps is None:
        return None
    return apps[0]

async def get_reportId(applicationId, stageId): # v.??
    url = f"{iq_url}/api/v2/reports/applications/{applicationId}"
    reports = await get_url(url)
    for report in reports:
        if report["stage"] in stageId:
            return report["reportHtmlUrl"].split("/")[-1]

async def get_policy_violations(publicId, reportId): # v.65
    url = f'{iq_url}/api/v2/applications/{publicId}/reports/{reportId}/policy'
    return await get_url(url)

async def get_raw_report(publicId, reportId): # v.??
    url = f'{iq_url}/api/v2/applications/{publicId}/reports/{reportId}'
    raw = await get_url(url) 
    for component in raw["components"]:
        issues = {}
        if component["securityData"] != None:
            for issue in component["securityData"]["securityIssues"]:
                issues.update({
                    issue["reference"]:{
                        "severity":issue["severity"],
                        "status":issue["status"]
                    }
                })
            raw.update({component["hash"]: issues })
    return raw

async def get_violation(policyViolationId): # v.94
    url = f'{iq_url}/api/v2/policyViolations/crossStage/{policyViolationId}'
    return await get_url(url)

async def get_recommendation(packageUrl, applicationId, stageId): # v.64
    # https://help.sonatype.com/iqserver/automating/rest-apis/component-remediation-rest-api---v2#ComponentRemediationRESTAPI-v2-AdvancedRecommendationStrategies
    component = {"packageUrl": packageUrl}
    url = f'{iq_url}/api/v2/components/remediation/application/{applicationId}?stageId={stageId}'
    return await post_url(url, component)

if __name__ == "__main__":
    asyncio.run(main())
