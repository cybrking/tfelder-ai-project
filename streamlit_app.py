# Change @st.cache_data to @st.cache
@st.cache
def convert_df(input_df):
    return input_df.to_csv(index=False).encode('utf-8')

# Define parameter_max_features_metric based on the selected parameter_max_features
parameter_max_features_metric = X.shape[1] if parameter_max_features == 'all' else parameter_max_features

# Update the parameter_criterion options to align with RandomForestRegressor
parameter_criterion_options = ['mse', 'mae', 'friedman_mse']
parameter_criterion = parameter_criterion_options[0] if parameter_criterion == 'squared_error' else parameter_criterion

# Transpose the rf_results DataFrame correctly
rf_results = pd.DataFrame({
    'Method': ['Random forest'],
    f'Training {parameter_criterion.capitalize()}': [train_mse],
    'Training R2': [train_r2],
    f'Test {parameter_criterion.capitalize()}': [test_mse],
    'Test R2': [test_r2]
})

# Reset the index for df_prediction after concatenation
df_prediction = pd.concat([df_train, df_test], axis=0).reset_index(drop=True)