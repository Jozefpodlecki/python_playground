from tensorflow import keras, saved_model
from tensorflow.keras import Sequential
from tensorflow.keras.layers import Conv2D, MaxPooling2D, Flatten, Dense, BatchNormalization, Activation

def get_cnn_model(input_shape, number_of_categories):
    return Sequential([
        Conv2D(
            64,
            kernel_size=(3, 3),
            activation='relu',
            input_shape=input_shape),
        MaxPooling2D((2, 2)),
        Conv2D(64,
            kernel_size=(3, 3),
            activation='relu'),
        MaxPooling2D((2, 2)),
        Conv2D(64,
            kernel_size=(3, 3),
            activation='relu'),
        Flatten(),
        Dense(128),
        BatchNormalization(),
        Activation("relu"),
        Dense(number_of_categories),
        BatchNormalization(),
        Activation("softmax")
    ])

       
