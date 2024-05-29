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
 
package org.spdx.library.model.v3.ai;

import org.spdx.core.IndividualUriValue;

/**
 * DO NOT EDIT - this file is generated by the Owl to Java Utility 
 * See: https://github.com/spdx/tools-java 
 * 
 * Lists the different safety risk type values that can be used to describe the safety 
 * risk of AI software according to [Article 20 of Regulation 765/2008/EC](https://ec.europa.eu/docsroom/documents/17107/attachments/1/translations/en/renditions/pdf). 
 */
public enum SafetyRiskAssessmentType implements IndividualUriValue {

	HIGH("high"),
	SERIOUS("serious"),
	LOW("low"),
	MEDIUM("medium");
	
	private String longName;
	
	private SafetyRiskAssessmentType(String longName) {
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
		return "https://spdx.org/rdf/v3/AI/SafetyRiskAssessmentType";
	}
}

