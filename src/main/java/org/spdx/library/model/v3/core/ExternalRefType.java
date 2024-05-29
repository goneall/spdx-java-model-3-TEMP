/**
 * Copyright (c) 2024 Source Auditor Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 * 
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */
 
package org.spdx.library.model.v3.core;

import org.spdx.library.IndividualUriValue;

/**
 * DO NOT EDIT - this file is generated by the Owl to Java Utility 
 * See: https://github.com/spdx/tools-java 
 * 
 * ExternalRefType specifies the type of an external reference. 
 */
public enum ExternalRefType implements IndividualUriValue {

	BINARY_ARTIFACT("binaryArtifact"),
	PURCHASE_ORDER("purchaseOrder"),
	CHAT("chat"),
	RELEASE_HISTORY("releaseHistory"),
	PRODUCT_METADATA("productMetadata"),
	FUNDING("funding"),
	BUILD_SYSTEM("buildSystem"),
	MAILING_LIST("mailingList"),
	NPM("npm"),
	SECURITY_ADVISORY("securityAdvisory"),
	SECURITY_POLICY("securityPolicy"),
	RELEASE_NOTES("releaseNotes"),
	DYNAMIC_ANALYSIS_REPORT("dynamicAnalysisReport"),
	RISK_ASSESSMENT("riskAssessment"),
	EOL_NOTICE("eolNotice"),
	SECURE_SOFTWARE_ATTESTATION("secureSoftwareAttestation"),
	SOCIAL_MEDIA("socialMedia"),
	SECURITY_PEN_TEST_REPORT("securityPenTestReport"),
	ISSUE_TRACKER("issueTracker"),
	PRIVACY_ASSESSMENT("privacyAssessment"),
	METRICS("metrics"),
	NUGET("nuget"),
	QUALITY_ASSESSMENT_REPORT("qualityAssessmentReport"),
	VCS("vcs"),
	STATIC_ANALYSIS_REPORT("staticAnalysisReport"),
	MAVEN_CENTRAL("maven-central"),
	LICENSE("license"),
	ALT_DOWNLOAD_LOCATION("altDownloadLocation"),
	CERTIFICATION_REPORT("certificationReport"),
	VULNERABILITY_DISCLOSURE_REPORT("vulnerabilityDisclosureReport"),
	SECURITY_ADVERSARY_MODEL("securityAdversaryModel"),
	BOWER("bower"),
	SOURCE_ARTIFACT("sourceArtifact"),
	EXPORT_CONTROL_ASSESSMENT("exportControlAssessment"),
	SECURITY_OTHER("securityOther"),
	COMPONENT_ANALYSIS_REPORT("componentAnalysisReport"),
	ALT_WEB_PAGE("altWebPage"),
	BUILD_META("buildMeta"),
	VULNERABILITY_EXPLOITABILITY_ASSESSMENT("vulnerabilityExploitabilityAssessment"),
	SUPPORT("support"),
	SECURITY_FIX("securityFix"),
	OTHER("other"),
	DOCUMENTATION("documentation"),
	SECURITY_THREAT_MODEL("securityThreatModel"),
	RUNTIME_ANALYSIS_REPORT("runtimeAnalysisReport");
	
	private String longName;
	
	private ExternalRefType(String longName) {
		this.longName = longName;
	}
	
	@Override
	public String getIndividualURI() {
		return getNameSpace() + "/" + getLongName();
	}
	
	public String getLongName() {
		return longName;
	}
	
	public String getNameSpace() {
		return "https://spdx.org/rdf/v3/Core/ExternalRefType";
	}
}

