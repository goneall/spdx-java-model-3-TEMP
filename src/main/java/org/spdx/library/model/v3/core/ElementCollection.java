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

import javax.annotation.Nullable;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.spdx.library.DefaultModelStore;
import org.spdx.library.InvalidSPDXAnalysisException;
import org.spdx.library.ModelCopyManager;
import org.spdx.library.model.ModelObject;
import org.spdx.library.model.v3.SpdxConstantsV3;
import org.spdx.storage.IModelStore;
import org.spdx.storage.IModelStore.IdType;
import org.spdx.storage.IModelStore.IModelStoreLock;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Objects;
import java.util.Optional;

/**
 * DO NOT EDIT - this file is generated by the Owl to Java Utility 
 * See: https://github.com/spdx/tools-java 
 * 
 * An SpdxCollection is a collection of Elements, not necessarily with unifying context. 
 */
public class ElementCollection extends Element  {

	Collection<ExternalMap> importss;
	Collection<Element> elements;
	Collection<Element> rootElements;
	
	/**
	 * Create the ElementCollection with default model store and generated anonymous ID
	 * @throws InvalidSPDXAnalysisException when unable to create the ElementCollection
	 */
	public ElementCollection() throws InvalidSPDXAnalysisException {
		this(DefaultModelStore.getDefaultModelStore().getNextId(IdType.Anonymous, null));
	}

	/**
	 * @param objectUri URI or anonymous ID for the ElementCollection
	 * @throws InvalidSPDXAnalysisException when unable to create the ElementCollection
	 */
	public ElementCollection(String objectUri) throws InvalidSPDXAnalysisException {
		this(DefaultModelStore.getDefaultModelStore(), objectUri, DefaultModelStore.getDefaultCopyManager(), true);
	}

	/**
	 * @param modelStore Model store where the ElementCollection is to be stored
	 * @param objectUri URI or anonymous ID for the ElementCollection
	 * @param copyManager Copy manager for the ElementCollection - can be null if copying is not required
	 * @param create true if ElementCollection is to be created
	 * @throws InvalidSPDXAnalysisException when unable to create the ElementCollection
	 */
	 @SuppressWarnings("unchecked")
	public ElementCollection(IModelStore modelStore, String objectUri, @Nullable ModelCopyManager copyManager,
			boolean create)	throws InvalidSPDXAnalysisException {
		super(modelStore, objectUri, copyManager, create);
		importss = (Collection<ExternalMap>)(Collection<?>)this.getObjectPropertyValueCollection(SpdxConstantsV3.CORE_PROP_IMPORTS, ExternalMap.class);
		elements = (Collection<Element>)(Collection<?>)this.getObjectPropertyValueCollection(SpdxConstantsV3.CORE_PROP_ELEMENT, Element.class);
		rootElements = (Collection<Element>)(Collection<?>)this.getObjectPropertyValueCollection(SpdxConstantsV3.CORE_PROP_ROOT_ELEMENT, Element.class);
	}

	/**
	 * Create the ElementCollection from the builder - used in the builder class
	 * @param builder Builder to create the ElementCollection from
	 * @throws InvalidSPDXAnalysisException when unable to create the ElementCollection
	 */
	 @SuppressWarnings("unchecked")
	protected ElementCollection(ElementCollectionBuilder builder) throws InvalidSPDXAnalysisException {
		super(builder);
		importss = (Collection<ExternalMap>)(Collection<?>)this.getObjectPropertyValueCollection(SpdxConstantsV3.CORE_PROP_IMPORTS, ExternalMap.class);
		elements = (Collection<Element>)(Collection<?>)this.getObjectPropertyValueCollection(SpdxConstantsV3.CORE_PROP_ELEMENT, Element.class);
		rootElements = (Collection<Element>)(Collection<?>)this.getObjectPropertyValueCollection(SpdxConstantsV3.CORE_PROP_ROOT_ELEMENT, Element.class);
		getImportss().addAll(builder.importss);
		getElements().addAll(builder.elements);
		getRootElements().addAll(builder.rootElements);
	}

	/* (non-Javadoc)
	 * @see org.spdx.library.model.ModelObject#getType()
	 */
	@Override
	public String getType() {
		return "Core.ElementCollection";
	}
	
	// Getters and Setters
	public Collection<ExternalMap> getImportss() {
		return importss;
	}
	public Collection<Element> getElements() {
		return elements;
	}
	public Collection<Element> getRootElements() {
		return rootElements;
	}
	
	
	
	@Override
	public String toString() {
		return "ElementCollection: "+getObjectUri();
	}
	
	/* (non-Javadoc)
	 * @see org.spdx.library.model.ModelObject#_verify(java.util.List)
	 */
	@Override
	public List<String> _verify(Set<String> verifiedIds, String specVersionForVerify, List<ProfileIdentifierType> profiles) {
		List<String> retval = new ArrayList<>();
		retval.addAll(super._verify(verifiedIds, specVersionForVerify, profiles));
		for (ExternalMap imports:importss) {
			retval.addAll(imports.verify(verifiedIds, specVersionForVerify, profiles));
		}
		for (Element element:elements) {
			retval.addAll(element.verify(verifiedIds, specVersionForVerify, profiles));
		}
		for (Element rootElement:rootElements) {
			retval.addAll(rootElement.verify(verifiedIds, specVersionForVerify, profiles));
		}
		return retval;
	}
	
	public static class ElementCollectionBuilder extends ElementBuilder {
	
		/**
		 * Create an ElementCollectionBuilder from another model object copying the modelStore and copyManager and using an anonymous ID
		 * @param from model object to copy the model store and copyManager from
		 * @throws InvalidSPDXAnalysisException
		 */
		public ElementCollectionBuilder(ModelObject from) throws InvalidSPDXAnalysisException {
			this(from, from.getModelStore().getNextId(IdType.Anonymous, null));
		}
	
		/**
		 * Create an ElementCollectionBuilder from another model object copying the modelStore and copyManager
		 * @param from model object to copy the model store and copyManager from
		 * @param objectUri URI for the object
		 * @param objectUri
		 */
		public ElementCollectionBuilder(ModelObject from, String objectUri) {
			this(from.getModelStore(), objectUri, from.getCopyManager());
			setStrict(from.isStrict());
		}
		
		/**
		 * Creates a ElementCollectionBuilder
		 * @param modelStore model store for the built ElementCollection
		 * @param objectUri objectUri for the built ElementCollection
		 * @param copyManager optional copyManager for the built ElementCollection
		 */
		public ElementCollectionBuilder(IModelStore modelStore, String objectUri, @Nullable ModelCopyManager copyManager) {
			super(modelStore, objectUri, copyManager);
		}
		
		Collection<ExternalMap> importss = new ArrayList<>();
		Collection<Element> elements = new ArrayList<>();
		Collection<Element> rootElements = new ArrayList<>();
		
		
		/**
		 * Adds a imports to the initial collection
		 * @parameter imports imports to add
		 * @return this for chaining
		**/
		public ElementCollectionBuilder addImports(ExternalMap imports) {
			if (Objects.nonNull(imports)) {
				importss.add(imports);
			}
			return this;
		}
		
		/**
		 * Adds all elements from a collection to the initial imports collection
		 * @parameter importsCollection collection to initialize the imports
		 * @return this for chaining
		**/
		public ElementCollectionBuilder addAllImports(Collection<ExternalMap> importsCollection) {
			if (Objects.nonNull(importsCollection)) {
				importss.addAll(importsCollection);
			}
			return this;
		}
		
		/**
		 * Adds a element to the initial collection
		 * @parameter element element to add
		 * @return this for chaining
		**/
		public ElementCollectionBuilder addElement(Element element) {
			if (Objects.nonNull(element)) {
				elements.add(element);
			}
			return this;
		}
		
		/**
		 * Adds all elements from a collection to the initial element collection
		 * @parameter elementCollection collection to initialize the element
		 * @return this for chaining
		**/
		public ElementCollectionBuilder addAllElement(Collection<Element> elementCollection) {
			if (Objects.nonNull(elementCollection)) {
				elements.addAll(elementCollection);
			}
			return this;
		}
		
		/**
		 * Adds a rootElement to the initial collection
		 * @parameter rootElement rootElement to add
		 * @return this for chaining
		**/
		public ElementCollectionBuilder addRootElement(Element rootElement) {
			if (Objects.nonNull(rootElement)) {
				rootElements.add(rootElement);
			}
			return this;
		}
		
		/**
		 * Adds all elements from a collection to the initial rootElement collection
		 * @parameter rootElementCollection collection to initialize the rootElement
		 * @return this for chaining
		**/
		public ElementCollectionBuilder addAllRootElement(Collection<Element> rootElementCollection) {
			if (Objects.nonNull(rootElementCollection)) {
				rootElements.addAll(rootElementCollection);
			}
			return this;
		}
	
		
		/**
		 * @return the ElementCollection
		 * @throws InvalidSPDXAnalysisException on any errors during build
		 */
		public ElementCollection build() throws InvalidSPDXAnalysisException {
			IModelStoreLock lock = modelStore.enterCriticalSection(false);
			try {
				return new ElementCollection(this);
			} finally {
				modelStore.leaveCriticalSection(lock);
			}
		}
	}
}
