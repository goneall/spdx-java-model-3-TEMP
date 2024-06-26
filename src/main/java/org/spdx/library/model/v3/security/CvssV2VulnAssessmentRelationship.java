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
 
package org.spdx.library.model.v3.security;

import javax.annotation.Nullable;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.spdx.library.DefaultModelStore;
import org.spdx.library.InvalidSPDXAnalysisException;
import org.spdx.library.ModelCopyManager;
import org.spdx.library.model.ModelObject;
import org.spdx.storage.IModelStore;
import org.spdx.storage.IModelStore.IdType;
import org.spdx.storage.IModelStore.IModelStoreLock;

import java.util.Arrays;
import java.util.Collections;
import java.util.Objects;
import java.util.Optional;

import org.spdx.library.model.v3.SpdxConstantsV3;
import org.spdx.library.model.v3.core.ProfileIdentifierType;

/**
 * DO NOT EDIT - this file is generated by the Owl to Java Utility 
 * See: https://github.com/spdx/tools-java 
 * 
 * A CvssV2VulnAssessmentRelationship relationship describes the determined score 
 * and vector of a vulnerability using version 2.0 of the Common Vulnerability Scoring 
 * System (CVSS) as defined on [https://www.first.org/cvss/v2/guide](https://www.first.org/cvss/v2/guide). 
 * It is intented to communicate the results of using a CVSS calculator. **Constraints** 
 * - The value of severity must be one of 'low', 'medium' or 'high' - The relationship 
 * type must be set to hasAssessmentFor. **Syntax** ```json { "@type": "CvssV2VulnAssessmentRelationship", 
 * "@id": "urn:spdx.dev:cvssv2-cve-2020-28498", "relationshipType": "hasAssessmentFor", 
 * "score": 4.3, "vector": "(AV:N/AC:M/Au:N/C:P/I:N/A:N)", "severity": "low", 
 * "from": "urn:spdx.dev:vuln-cve-2020-28498", "to": ["urn:product-acme-application-1.3"], 
 * "assessedElement": "urn:npm-elliptic-6.5.2", "externalRefs": [ { "@type": 
 * "ExternalRef", "externalRefType": "securityAdvisory", "locator": "https://nvd.nist.gov/vuln/detail/CVE-2020-28498" 
 * }, { "@type": "ExternalRef", "externalRefType": "securityAdvisory", "locator": 
 * "https://snyk.io/vuln/SNYK-JS-ELLIPTIC-1064899" }, { "@type": "ExternalRef", 
 * "externalRefType": "securityFix", "locator": "https://github.com/indutny/elliptic/commit/441b742" 
 * } ], "suppliedBy": ["urn:spdx.dev:agent-my-security-vendor"], "publishedTime": 
 * "2023-05-06T10:06:13Z" }, { "@type": "Relationship", "@id": "urn:spdx.dev:vulnAgentRel-1", 
 * "relationshipType": "publishedBy", "from": "urn:spdx.dev:cvssv2-cve-2020-28498", 
 * "to": ["urn:spdx.dev:agent-snyk"], "startTime": "2021-03-08T16:06:50Z" } 
 * ``` 
 */
public class CvssV2VulnAssessmentRelationship extends VulnAssessmentRelationship  {

	
	/**
	 * Create the CvssV2VulnAssessmentRelationship with default model store and generated anonymous ID
	 * @throws InvalidSPDXAnalysisException when unable to create the CvssV2VulnAssessmentRelationship
	 */
	public CvssV2VulnAssessmentRelationship() throws InvalidSPDXAnalysisException {
		this(DefaultModelStore.getDefaultModelStore().getNextId(IdType.Anonymous, null));
	}

	/**
	 * @param objectUri URI or anonymous ID for the CvssV2VulnAssessmentRelationship
	 * @throws InvalidSPDXAnalysisException when unable to create the CvssV2VulnAssessmentRelationship
	 */
	public CvssV2VulnAssessmentRelationship(String objectUri) throws InvalidSPDXAnalysisException {
		this(DefaultModelStore.getDefaultModelStore(), objectUri, DefaultModelStore.getDefaultCopyManager(), true);
	}

	/**
	 * @param modelStore Model store where the CvssV2VulnAssessmentRelationship is to be stored
	 * @param objectUri URI or anonymous ID for the CvssV2VulnAssessmentRelationship
	 * @param copyManager Copy manager for the CvssV2VulnAssessmentRelationship - can be null if copying is not required
	 * @param create true if CvssV2VulnAssessmentRelationship is to be created
	 * @throws InvalidSPDXAnalysisException when unable to create the CvssV2VulnAssessmentRelationship
	 */
	public CvssV2VulnAssessmentRelationship(IModelStore modelStore, String objectUri, @Nullable ModelCopyManager copyManager,
			boolean create)	throws InvalidSPDXAnalysisException {
		super(modelStore, objectUri, copyManager, create);
	}

	/**
	 * Create the CvssV2VulnAssessmentRelationship from the builder - used in the builder class
	 * @param builder Builder to create the CvssV2VulnAssessmentRelationship from
	 * @throws InvalidSPDXAnalysisException when unable to create the CvssV2VulnAssessmentRelationship
	 */
	protected CvssV2VulnAssessmentRelationship(CvssV2VulnAssessmentRelationshipBuilder builder) throws InvalidSPDXAnalysisException {
		super(builder);
		setScore(builder.score);
		setVector(builder.vector);
		setSeverity(builder.severity);
	}

	/* (non-Javadoc)
	 * @see org.spdx.library.model.ModelObject#getType()
	 */
	@Override
	public String getType() {
		return "Security.CvssV2VulnAssessmentRelationship";
	}
	
	// Getters and Setters
	
	
	/**
	 * @return the score
	 */
	public @Nullable Integer getScore() throws InvalidSPDXAnalysisException {
		Optional<Integer> retval = getIntegerPropertyValue(SpdxConstantsV3.SECURITY_PROP_SCORE);
		return retval.isPresent() ? retval.get() : null;
	}
	
	/**
	 * @param score the score to set
	 * @return this to chain setters
	 * @throws InvalidSPDXAnalysisException 
	 */
	public CvssV2VulnAssessmentRelationship setScore(@Nullable Integer score) throws InvalidSPDXAnalysisException {
		if (isStrict() && Objects.isNull(score)) {
			throw new InvalidSPDXAnalysisException("score is a required property");
		}
		setPropertyValue(SpdxConstantsV3.SECURITY_PROP_SCORE, score);
		return this;
	}

		/**
	 * @return the vector
	 */
	public Optional<String> getVector() throws InvalidSPDXAnalysisException {
		return getStringPropertyValue(SpdxConstantsV3.SECURITY_PROP_VECTOR);
	}
	/**
	 * @param vector the vector to set
	 * @return this to chain setters
	 * @throws InvalidSPDXAnalysisException 
	 */
	public CvssV2VulnAssessmentRelationship setVector(@Nullable String vector) throws InvalidSPDXAnalysisException {
		setPropertyValue(SpdxConstantsV3.SECURITY_PROP_VECTOR, vector);
		return this;
	}

		/**
	 * @return the severity
	 */
	public Optional<String> getSeverity() throws InvalidSPDXAnalysisException {
		return getStringPropertyValue(SpdxConstantsV3.SECURITY_PROP_SEVERITY);
	}
	/**
	 * @param severity the severity to set
	 * @return this to chain setters
	 * @throws InvalidSPDXAnalysisException 
	 */
	public CvssV2VulnAssessmentRelationship setSeverity(@Nullable String severity) throws InvalidSPDXAnalysisException {
		setPropertyValue(SpdxConstantsV3.SECURITY_PROP_SEVERITY, severity);
		return this;
	}
	
	
	@Override
	public String toString() {
		return "CvssV2VulnAssessmentRelationship: "+getObjectUri();
	}
	
	/* (non-Javadoc)
	 * @see org.spdx.library.model.ModelObject#_verify(java.util.List)
	 */
	@Override
	public List<String> _verify(Set<String> verifiedIds, String specVersionForVerify, List<ProfileIdentifierType> profiles) {
		List<String> retval = new ArrayList<>();
		retval.addAll(super._verify(verifiedIds, specVersionForVerify, profiles));
		try {
			Integer score = getScore();
			if (Objects.isNull(score) &&
					Collections.disjoint(profiles, Arrays.asList(new ProfileIdentifierType[] { ProfileIdentifierType.SECURITY }))) {
				retval.add("Missing score in CvssV2VulnAssessmentRelationship");
			}
		} catch (InvalidSPDXAnalysisException e) {
			retval.add("Error getting score for CvssV2VulnAssessmentRelationship: "+e.getMessage());
		}
		try {
			@SuppressWarnings("unused")
			Optional<String> vector = getVector();
		} catch (InvalidSPDXAnalysisException e) {
			retval.add("Error getting vector for CvssV2VulnAssessmentRelationship: "+e.getMessage());
		}
		try {
			@SuppressWarnings("unused")
			Optional<String> severity = getSeverity();
		} catch (InvalidSPDXAnalysisException e) {
			retval.add("Error getting severity for CvssV2VulnAssessmentRelationship: "+e.getMessage());
		}
		return retval;
	}
	
	public static class CvssV2VulnAssessmentRelationshipBuilder extends VulnAssessmentRelationshipBuilder {
	
		/**
		 * Create an CvssV2VulnAssessmentRelationshipBuilder from another model object copying the modelStore and copyManager and using an anonymous ID
		 * @param from model object to copy the model store and copyManager from
		 * @throws InvalidSPDXAnalysisException
		 */
		public CvssV2VulnAssessmentRelationshipBuilder(ModelObject from) throws InvalidSPDXAnalysisException {
			this(from, from.getModelStore().getNextId(IdType.Anonymous, null));
		}
	
		/**
		 * Create an CvssV2VulnAssessmentRelationshipBuilder from another model object copying the modelStore and copyManager
		 * @param from model object to copy the model store and copyManager from
		 * @param objectUri URI for the object
		 * @param objectUri
		 */
		public CvssV2VulnAssessmentRelationshipBuilder(ModelObject from, String objectUri) {
			this(from.getModelStore(), objectUri, from.getCopyManager());
			setStrict(from.isStrict());
		}
		
		/**
		 * Creates a CvssV2VulnAssessmentRelationshipBuilder
		 * @param modelStore model store for the built CvssV2VulnAssessmentRelationship
		 * @param objectUri objectUri for the built CvssV2VulnAssessmentRelationship
		 * @param copyManager optional copyManager for the built CvssV2VulnAssessmentRelationship
		 */
		public CvssV2VulnAssessmentRelationshipBuilder(IModelStore modelStore, String objectUri, @Nullable ModelCopyManager copyManager) {
			super(modelStore, objectUri, copyManager);
		}
		
		Integer score = null;
		String vector = null;
		String severity = null;
		
		
		/**
		 * Sets the initial value of score
		 * @parameter score value to set
		 * @return this for chaining
		**/
		public CvssV2VulnAssessmentRelationshipBuilder setScore(Integer score) {
			this.score = score;
			return this;
		}
		
		/**
		 * Sets the initial value of vector
		 * @parameter vector value to set
		 * @return this for chaining
		**/
		public CvssV2VulnAssessmentRelationshipBuilder setVector(String vector) {
			this.vector = vector;
			return this;
		}
		
		/**
		 * Sets the initial value of severity
		 * @parameter severity value to set
		 * @return this for chaining
		**/
		public CvssV2VulnAssessmentRelationshipBuilder setSeverity(String severity) {
			this.severity = severity;
			return this;
		}
	
		
		/**
		 * @return the CvssV2VulnAssessmentRelationship
		 * @throws InvalidSPDXAnalysisException on any errors during build
		 */
		public CvssV2VulnAssessmentRelationship build() throws InvalidSPDXAnalysisException {
			IModelStoreLock lock = modelStore.enterCriticalSection(false);
			try {
				return new CvssV2VulnAssessmentRelationship(this);
			} finally {
				modelStore.leaveCriticalSection(lock);
			}
		}
	}
}
