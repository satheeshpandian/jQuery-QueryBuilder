/**
 * @module JsonLogicSupportPlugin
 * @description Allows to export rules as a JsonLogic rules object as well as populating the builder from a JsonLogic rules object.
 */

QueryBuilder.defaults({
    jsonLogicOperators: {
        // @formatter:off
        equal:            { symbol: '==', func: function(f, v) { return [{'var': f}, v[0]]; } },
        not_equal:        { symbol: '!=', func: function(f, v) { return [{'var': f}, v[0]]; } },
        in:               { symbol: 'in', func: function(f, v) { return [{'var': f}, v]; } },
        not_in:           { symbol: '!', func: function(f, v) { return { 'in': [{'var': f}, v] }; } },
        less:             { symbol: '<', func: function(f, v) { return [{'var': f}, v[0]]; } },
        less_or_equal:    { symbol: '<=', func: function(f, v) { return [{'var': f}, v[0]]; } },
        greater:          { symbol: '>', func: function(f, v) { return [{'var': f}, v[0]]; } },
        greater_or_equal: { symbol: '>=', func: function(f, v) { return [{'var': f}, v[0]]; } },
        between:          { symbol: '<=', func: function(f, v) { return [v[0], {'var': f}, v[1]]; } },
        not_between:      { symbol: '!', func: function(f, v) { return { '<=': [v[0], {'var': f}, v[1]] }; } },
        begins_with:      { symbol: 'startsWith', func: function(f, v) { return [v[0], {'var': f}]; } },
        not_begins_with:  { symbol: '!', func: function(f, v) { return { 'startsWith': [v[0], {'var': f}] }; } },
        contains:         { symbol: 'in', func: function(f, v) { return [v[0], {'var': f}]; } },
        not_contains:     { symbol: '!', func: function(f, v) { return { 'in': [v[0], {'var': f}] }; } },
        ends_with:        { symbol: 'endsWith', func: function(f, v) { return [v[0], {'var': f}]; } },
        not_ends_with:    { symbol: '!', func: function(f, v) { return { 'endsWith': [v[0], {'var': f}] }; } },
        is_empty:         { symbol: '===', func: function(f, v) { return [{'var': f}, '']; } },
        is_not_empty:     { symbol: '!==', func: function(f, v) { return [{'var': f}, '']; } },
        is_null:          { symbol: '===', func: function(f, v) { return [{'var': f}, null]; } },
        is_not_null:      { symbol: '!==', func: function(f, v) { return [{'var': f}, null]; } }
        // @formatter:on
    },

    jsonLogicRuleOperators: {
        $ne: function(v) {
            v = v.$ne;
            return {
                'val': v,
                'op': v === null ? 'is_not_null' : (v === '' ? 'is_not_empty' : 'not_equal')
            };
        },
        eq: function(v) {
            return {
                'val': v,
                'op': v === null ? 'is_null' : (v === '' ? 'is_empty' : 'equal')
            };
        },
        $regex: function(v) {
            v = v.$regex;
            if (v.slice(0, 4) == '^(?!' && v.slice(-1) == ')') {
                return { 'val': v.slice(4, -1), 'op': 'not_begins_with' };
            }
            else if (v.slice(0, 5) == '^((?!' && v.slice(-5) == ').)*$') {
                return { 'val': v.slice(5, -5), 'op': 'not_contains' };
            }
            else if (v.slice(0, 4) == '(?<!' && v.slice(-2) == ')$') {
                return { 'val': v.slice(4, -2), 'op': 'not_ends_with' };
            }
            else if (v.slice(-1) == '$') {
                return { 'val': v.slice(0, -1), 'op': 'ends_with' };
            }
            else if (v.slice(0, 1) == '^') {
                return { 'val': v.slice(1), 'op': 'begins_with' };
            }
            else {
                return { 'val': v, 'op': 'contains' };
            }
        },
        between: function(v) {
            return { 'val': [v.$gte, v.$lte], 'op': 'between' };
        },
        not_between: function(v) {
            return { 'val': [v.$lt, v.$gt], 'op': 'not_between' };
        },
        $in: function(v) {
            return { 'val': v.$in, 'op': 'in' };
        },
        $nin: function(v) {
            return { 'val': v.$nin, 'op': 'not_in' };
        },
        $lt: function(v) {
            return { 'val': v.$lt, 'op': 'less' };
        },
        $lte: function(v) {
            return { 'val': v.$lte, 'op': 'less_or_equal' };
        },
        $gt: function(v) {
            return { 'val': v.$gt, 'op': 'greater' };
        },
        $gte: function(v) {
            return { 'val': v.$gte, 'op': 'greater_or_equal' };
        }
    }
});

QueryBuilder.extend({
    /**
     * Returns rules as a JsonLogic rules object
     * @memberof module:JsonLogicSupportPlugin
     * @param {object} [data] - current rules by default
     * @returns {object}
     * @fires module:JsonLogicSupportPlugin.changer:getJsonLogicField
     * @fires module:JsonLogicSupportPlugin.changer:ruleToJsonLogic
     * @fires module:JsonLogicSupportPlugin.changer:groupToJsonLogic
     * @throws UndefinedJsonLogicConditionError, UndefinedJsonLogicOperatorError
     */
    getJsonLogic: function(data) {
        data = (data === undefined) ? this.getRules() : data;

        var self = this;

        return (function parse(group) {
            if (!group.condition) {
                group.condition = self.settings.default_condition;
            }
            if (['AND', 'OR'].indexOf(group.condition.toUpperCase()) === -1) {
                Utils.error('UndefinedJsonLogicCondition', 'Unable to build JsonLogic rules with condition "{0}"', group.condition);
            }

            if (!group.rules) {
                return {};
            }

            var parts = [];

            group.rules.forEach(function(rule) {
                if (rule.rules && rule.rules.length > 0) {
                    parts.push(parse(rule));
                }
                else {
                    var mdb = self.settings.jsonLogicOperators[rule.operator];
                    var ope = self.getOperatorByType(rule.operator);
                    var values = [];

                    if (mdb === undefined) {
                        Utils.error('UndefinedJsonLogicOperator', 'Unknown JsonLogic operation for operator "{0}"', rule.operator);
                    }

                    if (ope.nb_inputs !== 0) {
                        if (!(rule.value instanceof Array)) {
                            rule.value = [rule.value];
                        }

                        rule.value.forEach(function(v) {
                            values.push(Utils.changeType(v, rule.type, false));
                        });
                    }

                    /**
                     * Modifies the JsonLogic field used by a rule
                     * @event changer:getJsonLogicField
                     * @memberof module:JsonLogicSupportPlugin
                     * @param {string} field
                     * @param {Rule} rule
                     * @returns {string}
                     */
                    var field = self.change('getJsonLogicField', rule.field, rule);
                    console.log('field is [' + field + ']');

                    var ruleExpression = {};
                    ruleExpression[mdb.symbol] = mdb.func.call(self, field, values);

                    /**
                     * Modifies the JsonLogic expression generated for a rule
                     * @event changer:ruleToJsonLogic
                     * @memberof module:JsonLogicSupportPlugin
                     * @param {object} expression
                     * @param {Rule} rule
                     * @param {*} value
                     * @param {function} valueWrapper - function that takes the value and adds the operator
                     * @returns {object}
                     */
                    parts.push(self.change('ruleToJsonLogic', ruleExpression, rule, values, mdb));
                }
            });

            var groupExpression = {};
            groupExpression[group.condition.toLowerCase()] = parts;

            /**
             * Modifies the JsonLogic expression generated for a group
             * @event changer:groupToJsonLogic
             * @memberof module:JsonLogicSupportPlugin
             * @param {object} expression
             * @param {Group} group
             * @returns {object}
             */
            return self.change('groupToJsonLogic', groupExpression, group);
        }(data));
    },

    /**
     * Converts a JsonLogic query to rules
     * @memberof module:JsonLogicSupportPlugin
     * @param {object} query
     * @returns {object}
     * @fires module:JsonLogicSupportPlugin.changer:parseJsonLogicNode
     * @fires module:JsonLogicSupportPlugin.changer:getJsonLogicFieldID
     * @fires module:JsonLogicSupportPlugin.changer:jsonLogicToRule
     * @fires module:JsonLogicSupportPlugin.changer:jsonLogicToGroup
     * @throws JsonLogicParseError, UndefinedJsonLogicConditionError, UndefinedJsonLogicOperatorError
     */
    getRulesFromJsonLogic: function(query) {
        if (query === undefined || query === null) {
            return null;
        }

        var self = this;

        /**
         * Custom parsing of a JsonLogic expression, you can return a sub-part of the expression, or a well formed group or rule JSON
         * @event changer:parseJsonLogicNode
         * @memberof module:JsonLogicSupportPlugin
         * @param {object} expression
         * @returns {object} expression, rule or group
         */
        query = self.change('parseJsonLogicNode', query);

        // a plugin returned a group
        if ('rules' in query && 'condition' in query) {
            return query;
        }

        // a plugin returned a rule
        if ('id' in query && 'operator' in query && 'value' in query) {
            return {
                condition: this.settings.default_condition,
                rules: [query]
            };
        }

        var key = andOr(query);
        if (!key) {
            Utils.error('JsonLogicParse', 'Invalid JsonLogic query format');
        }

        return (function parse(data, topKey) {
            var rules = data[topKey];
            var parts = [];

            rules.forEach(function(data) {
                // allow plugins to manually parse or handle special cases
                data = self.change('parseJsonLogicNode', data);

                // a plugin returned a group
                if ('rules' in data && 'condition' in data) {
                    parts.push(data);
                    return;
                }

                // a plugin returned a rule
                if ('id' in data && 'operator' in data && 'value' in data) {
                    parts.push(data);
                    return;
                }

                var key = andOr(data);
                if (key) {
                    parts.push(parse(data, key));
                }
                else {
                    var field = Object.keys(data)[0];
                    console.log('field is [' + field + ']');
                    var value = data[field];
                    console.log('value is [' + value + ']');

                    var operator = determineJsonLogicOperator(value, field);
                    if (operator === undefined) {
                        Utils.error('JsonLogicParse', 'Invalid JsonLogic query format');
                    }

                    var mdbrl = self.settings.jsonLogicRuleOperators[operator];
                    if (mdbrl === undefined) {
                        Utils.error('UndefinedJsonLogicOperator', 'JSON Rule operation unknown for operator "{0}"', operator);
                    }

                    var opVal = mdbrl.call(self, value);

                    /**
                     * Returns a filter identifier from the JsonLogic field
                     * @event changer:getJsonLogicFieldID
                     * @memberof module:JsonLogicSupportPlugin
                     * @param {string} field
                     * @param {*} value
                     * @returns {string}
                     */
                    var id = self.change('getJsonLogicFieldID', field, value);
                    console.log('id is [' + id + ']');

                    /**
                     * Modifies the rule generated from the JsonLogic expression
                     * @event changer:jsonLogicToRule
                     * @memberof module:JsonLogicSupportPlugin
                     * @param {object} rule
                     * @param {object} expression
                     * @returns {object}
                     */
                    var rule = self.change('jsonLogicToRule', {
                        id: id,
                        field: field,
                        operator: opVal.op,
                        value: opVal.val
                    }, data);

                    parts.push(rule);
                }
            });

            /**
             * Modifies the group generated from the JsonLogic expression
             * @event changer:jsonLogicToGroup
             * @memberof module:JsonLogicSupportPlugin
             * @param {object} group
             * @param {object} expression
             * @returns {object}
             */
            return self.change('jsonLogicToGroup', {
                condition: topKey.replace('$', '').toUpperCase(),
                rules: parts
            }, data);
        }(query, key));
    },

    /**
     * Sets rules a from JsonLogic query
     * @memberof module:JsonLogicSupportPlugin
     * @see module:JsonLogicSupportPlugin.getRulesFromJsonLogic
     */
    setRulesFromJsonLogic: function(query) {
        this.setRules(this.getRulesFromJsonLogic(query));
    }
});

/**
 * Finds which operator is used in a JsonLogic sub-object
 * @memberof module:JsonLogicSupportPlugin
 * @param {*} value
 * @returns {string|undefined}
 * @private
 */
function determineJsonLogicOperator(value) {
    if (value !== null && typeof value == 'object') {
        var subkeys = Object.keys(value);

        if (subkeys.length === 1) {
            return subkeys[0];
        }
        else {
            if (value.$gte !== undefined && value.$lte !== undefined) {
                return 'between';
            }
            if (value.$lt !== undefined && value.$gt !== undefined) {
                return 'not_between';
            }
            else if (value.$regex !== undefined) { // optional $options
                return '$regex';
            }
            else {
                return;
            }
        }
    }
    else {
        return 'eq';
    }
}

/**
 * Returns the key corresponding to "or" or "and"
 * @memberof module:JsonLogicSupportPlugin
 * @param {object} data
 * @returns {string}
 * @private
 */
function andOr(data) {
    var keys = Object.keys(data);

    for (var i = 0, l = keys.length; i < l; i++) {
        if (keys[i].toLowerCase() == 'or' || keys[i].toLowerCase() == 'and') {
            return keys[i];
        }
    }

    return undefined;
}
