/**
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Source Auditor Inc.
 */
package org.spdx.library.model.v3;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spdx.core.CoreModelObject;
import org.spdx.core.IModelCopyManager;
import org.spdx.core.IndividualUriValue;
import org.spdx.core.InvalidSPDXAnalysisException;
import org.spdx.core.SimpleUriValue;
import org.spdx.core.SpdxInvalidTypeException;
import org.spdx.library.model.v3.core.CreationInfo;
import org.spdx.library.model.v3.core.Element;
import org.spdx.library.model.v3.simplelicensing.AnyLicenseInfo;
import org.spdx.storage.IModelStore;
import org.spdx.storage.PropertyDescriptor;

/**
 * @author Gary O'Neall
 *
 */
public abstract class ModelObjectV3 extends CoreModelObject {
	
	//TODO: Handle SpdxDocument external refs and spec version updates
	
	static final Logger logger = LoggerFactory.getLogger(ModelObjectV3.class);

	/**
	 * @throws InvalidSPDXAnalysisException
	 */
	public ModelObjectV3() throws InvalidSPDXAnalysisException {
		super(SpdxConstantsV3.MODEL_SPEC_VERSION);
	}

	/**
	 * @param objectUri
	 * @throws InvalidSPDXAnalysisException
	 */
	public ModelObjectV3(String objectUri) throws InvalidSPDXAnalysisException {
		super(objectUri, SpdxConstantsV3.MODEL_SPEC_VERSION);
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param modelStore
	 * @param objectUri
	 * @param copyManager
	 * @param create
	 * @throws InvalidSPDXAnalysisException
	 */
	public ModelObjectV3(IModelStore modelStore, String objectUri,
			IModelCopyManager copyManager, boolean create)
			throws InvalidSPDXAnalysisException {
		super(modelStore, objectUri, copyManager, create, SpdxConstantsV3.MODEL_SPEC_VERSION);
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param builder
	 * @throws InvalidSPDXAnalysisException
	 */
	public ModelObjectV3(CoreModelObjectBuilder builder)
			throws InvalidSPDXAnalysisException {
		super(builder, SpdxConstantsV3.MODEL_SPEC_VERSION);
		// TODO Auto-generated constructor stub
	}

	
	/**
	 * @param specVersion Version of the SPDX spec to verify against
	 * @param verifiedElementUris list of all element object URIs which have already been verified - prevents infinite recursion
	 * @param profiles list of profile identifiers to validate against
	 * @return Any verification errors or warnings associated with this object
	 */
	public List<String> verify(Set<String> verifiedElementUris, String specVersion, List<IndividualUriValue> profiles) {
		if (verifiedElementUris.contains(this.objectUri)) {
			return new ArrayList<>();
		} else {
			// The verifiedElementId is added in the SpdxElement._verify method
			return _verify(verifiedElementUris, specVersion, profiles);
		}
	}
	
	/**
	 * @param specVersion Version of the SPDX spec to verify against
	 * @param verifiedElementUris list of all element object URIs which have already been verified - prevents infinite recursion
	 * @return Any verification errors or warnings associated with this object
	 */
	public List<String> verify(Set<String> verifiedElementUris, String specVersion) {
		List<IndividualUriValue> profiles = new ArrayList<>();
		if (this instanceof Element) {
			CreationInfo creationInfo;
			try {
				creationInfo = ((Element)this).getCreationInfo();
				if (Objects.nonNull(creationInfo)) {
					profiles = new ArrayList<>(creationInfo.getProfiles());
				}
			} catch (InvalidSPDXAnalysisException e) {
				logger.error("Error getting element profile for verification", e);
			}
		}
		return verify(verifiedElementUris, specVersion, profiles);
	}
	
	/**
	 * @param specVersion Version of the SPDX spec to verify against
	 * @param profiles list of profile identifiers to validate against
	 * @return Any verification errors or warnings associated with this object
	 */
	public List<String> verify(String specVersion, List<IndividualUriValue> profiles) {
		return verify(new HashSet<String>(), specVersion, profiles);
	}
	
	/**
	 * Converts property values to an AnyLicenseInfo if possible - if NONE or NOASSERTION URI value, convert to the appropriate license
	 * @param propertyDescriptor descriptor for the property
	 * @return AnyLicenseInfo license info for the property
	 * @throws InvalidSPDXAnalysisException
	 */
	@SuppressWarnings("unchecked")
	protected Optional<AnyLicenseInfo> getAnyLicenseInfoPropertyValue(PropertyDescriptor propertyDescriptor) throws InvalidSPDXAnalysisException {
		Optional<Object> result = getObjectPropertyValue(propertyDescriptor);
		if (!result.isPresent()) {
			return Optional.empty();
		} else if (result.get() instanceof AnyLicenseInfo) {
			return (Optional<AnyLicenseInfo>)(Optional<?>)result;
		} else if (result.get() instanceof SimpleUriValue) {
			Object val = ((SimpleUriValue)(result.get())).toModelObject(modelStore, copyManager, specVersion);
			if (val instanceof AnyLicenseInfo) {
				return Optional.of((AnyLicenseInfo)val);
			} else {
				logger.error("Invalid type for AnyLicenseInfo property: "+val.getClass().toString());
				throw new SpdxInvalidTypeException("Invalid type for AnyLicenseInfo property: "+val.getClass().toString());
			}
		} else {
			logger.error("Invalid type for AnyLicenseInfo property: "+result.get().getClass().toString());
			throw new SpdxInvalidTypeException("Invalid type for AnyLicenseInfo property: "+result.get().getClass().toString());
		}
	}
	
	/**
	 * Converts property values to an SpdxElement if possible - if individual value, convert to the appropriate SpdxElement
	 * @param propertyDescriptor Descriptor for the property
	 * @return SpdxElement stored
	 * @throws InvalidSPDXAnalysisException
	 */
	@SuppressWarnings("unchecked")
	protected Optional<Element> getElementPropertyValue(PropertyDescriptor propertyDescriptor) throws InvalidSPDXAnalysisException {
		Optional<Object> result = getObjectPropertyValue(propertyDescriptor);
		if (!result.isPresent()) {
			return Optional.empty();
		} else if (result.get() instanceof Element) {
			return (Optional<Element>)(Optional<?>)result;
		} else if (result.get() instanceof SimpleUriValue) {
			Object val = ((SimpleUriValue)(result.get())).toModelObject(modelStore, copyManager, specVersion);
			if (val instanceof Element) {
				return Optional.of((Element)val);
			} else {
				logger.error("Invalid type for Element property: "+val.getClass().toString());
				throw new SpdxInvalidTypeException("Invalid type for Element property: "+val.getClass().toString());
			}
		} else {
			logger.error("Invalid type for SpdxElement property: "+result.get().getClass().toString());
			throw new SpdxInvalidTypeException("Invalid type for SpdxElement property: "+result.get().getClass().toString());
		}
	}
	
	/**
	 * @param propertyDescriptor property descriptor for the object in question
	 * @return true if the object is "to" part of a relationship
	 */
	public boolean isRelatedElement(PropertyDescriptor propertyDescriptor) {
		return SpdxConstantsV3.CORE_PROP_TO.equals(propertyDescriptor);
	}
	
}
